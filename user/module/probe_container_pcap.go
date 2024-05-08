package module

import (
	"cacapture/user/config"
	"cacapture/user/event"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

type PodNetworkInfo struct {
	Podname  string
	Ifname   string
	Ifindex  int
	NsHandel netns.NsHandle
}

func (m *MContainerProbe) setupManagerPcap() error {
	var ifname string // binaryPath

	ifname = m.conf.(*config.ContainerConfig).Ifname
	m.ifName = ifname

	var probes []*manager.Probe
	var podNetworksMap map[string]*PodNetworkInfo = make(map[string]*PodNetworkInfo)

	config, err := clientcmd.BuildConfigFromFlags("", "/etc/kubernetes/kubelet.conf")
	if err != nil {
		m.logger.Println("cannot find the kubernetes conf in this node ", err)
	}

	var podNameList = m.conf.GetPodName()
	m.logger.Println("CACAPTURE::\t pod name list is", podNameList)

	if m.conf.GetContainerPID() == 0 && len(podNameList) != 0 {
		// don't set the pid for the any container in pod, but give the pod name
		// search the first net device which is not the lo

		conn, err := grpc.Dial("unix:///run/containerd/containerd.sock", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			panic("failed to connect: " + err.Error())
		}
		defer conn.Close()

		runtimeService := runtimeapi.NewRuntimeServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// 获取容器列表
		containers, err := runtimeService.ListContainers(ctx, &runtimeapi.ListContainersRequest{})
		if err != nil {
			panic("failed to list containers: " + err.Error())
		}

		for _, container := range containers.Containers {
			// fmt.Printf("Container ID: %s\n", container.Id)
			// 可以进一步获取容器状态或执行其他操作
			status, err := runtimeService.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{ContainerId: container.Id, Verbose: true})
			if err != nil {
				m.logger.Printf("Error getting status for container %s: %s\n", container.Id, err)
				continue
			}
			if status.Status.State != runtimeapi.ContainerState_CONTAINER_RUNNING {
				continue
			}
			podNs := status.Status.Labels["io.kubernetes.pod.namespace"]
			if podNs == "kube-system" {
				continue
			}
			podName := status.Status.Labels["io.kubernetes.pod.name"]
			// 确保每个pod只有一个interface被抓取

			if _, exists := podNetworksMap[podName]; exists {

				continue
			}

			pid, err := getPid(status)
			fmt.Println(podNameList)
			// fmt.Println("the pid is", pid)
			if err != nil {
				m.logger.Println("Cann't get the pid from container%v", container.Id, err)
			}
			if contains(podNameList, "all") {
				// 如果是all,则所有的pod都要添加tc
				addPodNetworkInfo(pid, podName, podNetworksMap, config)
			} else if contains(podNameList, podName) {
				// 否则判断pod是否在podNameList中，再则加入
				addPodNetworkInfo(pid, podName, podNetworksMap, config)
			} else {
				// 不在则直接掠过
				fmt.Println(podName)
				continue
			}

		}

	} else {
		// 对于docker 模式，则直接将第一块不是回环的虚拟网卡添加
		addPodNetworkInfo(int(m.conf.GetContainerPID()), "", podNetworksMap, nil)
	}
	m.logger.Println("CACAPTURE::\tgive the pod infomation as follows")
	for _, podInfo := range podNetworksMap {
		m.logger.Printf("CACAPTURE::\tthe pod name is %s,the iface name is %s,the iface index is %v, the ns is %s\n", podInfo.Podname, podInfo.Ifname, podInfo.Ifindex, podInfo.NsHandel.String())
	}
	if len(podNetworksMap) == 1 {
		m.logger.Println("only have one pod")
		for _, podInfo := range podNetworksMap {
			probes = append(probes, &manager.Probe{
				Section:          "classifier/egress",
				EbpfFuncName:     "egress_cls_func",
				Ifname:           podInfo.Ifname,
				Ifindex:          int32(podInfo.Ifindex),
				IfindexNetns:     uint64(podInfo.NsHandel),
				NetworkDirection: manager.Egress,
			})
			probes = append(probes, &manager.Probe{
				Section:          "classifier/ingress",
				EbpfFuncName:     "ingress_cls_func",
				Ifname:           podInfo.Ifname,
				Ifindex:          int32(podInfo.Ifindex),
				IfindexNetns:     uint64(podInfo.NsHandel),
				NetworkDirection: manager.Ingress,
			})

		}

	} else {

		for _, podInfo := range podNetworksMap {
			newEgressProbe := &manager.Probe{
				Section:          "classifier/egress",
				EbpfFuncName:     "egress_cls_func",
				NetworkDirection: manager.Egress,
				UID:              podInfo.Ifname + podInfo.NsHandel.String(),
				Ifname:           podInfo.Ifname,
				Ifindex:          int32(podInfo.Ifindex),
				IfindexNetns:     uint64(podInfo.NsHandel),
			}

			// 创建新的 ingressProbe 实例
			newIngressProbe := &manager.Probe{
				Section:          "classifier/ingress",
				EbpfFuncName:     "ingress_cls_func",
				NetworkDirection: manager.Ingress,
				UID:              podInfo.Ifname + podInfo.NsHandel.String(),
				Ifname:           podInfo.Ifname,
				Ifindex:          int32(podInfo.Ifindex),
				IfindexNetns:     uint64(podInfo.NsHandel),
			}

			probes = append(probes, newEgressProbe, newIngressProbe)

		}

	}

	// binaryPath = m.conf.(*config.ContainerConfig).Openssl
	m.sslBpfFile = "tc.o" // assinged by caffein
	// m.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", m.Name(), m.conf.(*config.ContainerConfig).ElfType, binaryPath)
	// m.logger.Printf("%s\tIfname:%s, Ifindex:%d,  Port:%d, Pcapng filepath:%s\n", m.Name(), m.ifName, m.ifIdex, m.conf.(*config.ContainerConfig).Port, m.pcapngFilename)
	// m.logger.Printf("%s\tHook masterKey function:%s\n", m.Name(), m.masterHookFunc)
	netIfs, err := net.Interfaces()
	if err != nil {
		return err
	}

	err = m.createPcapng(netIfs)
	if err != nil {
		return err
	}

	m.bpfManager = &manager.Manager{
		Probes: probes,

		Maps: []*manager.Map{
			// {
			// 	Name: "mastersecret_events",
			// },
			{
				Name: "skb_events",
			},
		},
	}

	m.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if m.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		m.bpfManagerOptions.ConstantEditors = m.constantEditor()
	}
	return nil
}
func (m *MContainerProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(m.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(m.conf.GetUid()),
		},
		{
			Name:  "target_port",
			Value: uint64(m.conf.(*config.ContainerConfig).Port),
		},
	}

	if m.conf.GetPid() <= 0 {
		m.logger.Printf("%s\ttarget all process. \n", m.Name())
	} else {
		m.logger.Printf("%s\ttarget PID:%d \n", m.Name(), m.conf.GetPid())
	}

	if m.conf.GetUid() <= 0 {
		m.logger.Printf("%s\ttarget all users. \n", m.Name())
	} else {
		m.logger.Printf("%s\ttarget UID:%d \n", m.Name(), m.conf.GetUid())
	}

	return editor
}

func (m *MContainerProbe) initDecodeFunPcap() error {
	//SkbEventsMap 与解码函数映射
	SkbEventsMap, found, err := m.bpfManager.GetMap("skb_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:skb_events")
	}
	m.eventMaps = append(m.eventMaps, SkbEventsMap)
	sslEvent := &event.TcSkbEvent{}
	//sslEvent.SetModule(m)
	m.eventFuncMaps[SkbEventsMap] = sslEvent

	// MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_events")
	// if err != nil {
	// 	return err
	// }
	// if !found {
	// 	return errors.New("cant found map:mastersecret_events")
	// }
	// m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

	// var masterkeyEvent event.IEventStruct

	// masterkeyEvent = &event.MasterSecretEvent{}

	// //masterkeyEvent.SetModule(m)
	// m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func getPid(status *runtimeapi.ContainerStatusResponse) (int, error) {
	infoJSON, ok := status.Info["info"]
	if !ok {
		return -1, errors.New("info key does not exist in the status map")
	}
	var info map[string]interface{}
	err := json.Unmarshal([]byte(infoJSON), &info)
	if err != nil {
		return -1, err
	}
	// 访问嵌套字段
	pidValue, ok := info["pid"]
	if !ok {
		return -1, errors.New("pid key is missing in info")
	}
	return int(pidValue.(float64)), nil

}
func addPodNetworkInfo(pid int, podName string, podNetworksMap map[string]*PodNetworkInfo, config *rest.Config) error {
	var podIP string
	if config == nil {
		podIP = ""
	} else {
		var err error
		podIP, err = getPodIP(podName, config)
		if err != nil {
			return err
		}
	}

	originalNs, _ := netns.Get()
	defer netns.Set(originalNs)
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	nsHandle, err := netns.GetFromPath(nsPath)
	if err != nil {
		return err
	}

	netns.Set(nsHandle)
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	var selectedInterface net.Interface
	found := false
	for _, iface := range ifaces {
		if podIP != "" { // pod 模式
			addrs, err := iface.Addrs()
			if err != nil {
				return err
			}
			for _, addr := range addrs {
				// 尝试将地址断言为 *net.IPNet 类型
				switch v := addr.(type) {
				case *net.IPNet:
					// 检查 IP 地址是否匹配 Pod IP
					if v.IP.String() == podIP {
						selectedInterface = iface
						found = true
						break
					}
				}
			}
			if found {
				break
			}

		} else { //docker 模式
			if iface.Flags&net.FlagLoopback != net.FlagLoopback {
				selectedInterface = iface
				break
			}
		}

	}
	podNetworksMap[podName] = &PodNetworkInfo{
		Podname:  podName,
		Ifname:   selectedInterface.Name,
		Ifindex:  selectedInterface.Index,
		NsHandel: nsHandle,
	}
	return nil
}
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func getPodIP(podName string, config *rest.Config) (string, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", errors.New("Cann't get the clientset from config")
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", errors.New("Cann't get the ns form clientset")

	}
	for _, namespace := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(namespace.Name).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, pod := range pods.Items {
			if pod.Name == podName {
				return pod.Status.PodIP, nil
			}
		}
	}
	return "", errors.New("Cann't find the pod for given pod name")

}
