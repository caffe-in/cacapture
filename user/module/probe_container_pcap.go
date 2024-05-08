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
	"github.com/docker/docker/client"
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

	if m.conf.GetMode() == "Containerd" {
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

			// fmt.Println("the pid is", pid)
			if err != nil {
				m.logger.Println("Cann't get the pid from container%v", container.Id, err)
			}
			if contains(podNameList, "all") {
				// 如果是all,则所有的pod都要添加tc
				err := addPodNetworkInfo(pid, podName, podNetworksMap, config, m.conf.GetPodNsName())
				if err != nil {
					m.logger.Println("add pod networkinfo err: ", err)
				}
			} else if contains(podNameList, podName) {
				// 否则判断pod是否在podNameList中，再则加入
				err := addPodNetworkInfo(pid, podName, podNetworksMap, config, m.conf.GetPodNsName())
				if err != nil {
					m.logger.Println("add pod networkinfo err: ", err)
				}

			} else {
				// 不在则直接掠过
				continue
			}

		}

	} else if m.conf.GetMode() == "Docker" {
		// 对于docker 模式，则直接将第一块不是回环的虚拟网卡添加
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			m.logger.Println(" Cann't find the client for Docker")
			return err
		}
		containerJSON, err := cli.ContainerInspect(context.Background(), m.conf.GetContainerID())
		if err != nil {
			m.logger.Println(" Cann't find the PID for Docker Container")
			return err
		}
		addPodNetworkInfo(int(containerJSON.State.Pid), "Docker Mode", podNetworksMap, nil, "")
	} else {
		m.logger.Println("Other Container Runtime doesn't support")
	}
	m.logger.Println("give the pod infomation as follows")
	for _, podInfo := range podNetworksMap {
		m.logger.Printf("pod name:%s,iface:%s,iface index:%v,ns:%s\n", podInfo.Podname, podInfo.Ifname, podInfo.Ifindex, podInfo.NsHandel.String())
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

	m.sslBpfFile = "tc.o" // assinged by caffein

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

	return nil
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
	m.eventFuncMaps[SkbEventsMap] = sslEvent

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
func addPodNetworkInfo(pid int, podName string, podNetworksMap map[string]*PodNetworkInfo, config *rest.Config, podNsName string) error {
	var podIP string
	if config == nil {
		podIP = ""
	} else {
		var err error
		podIP, err = getPodIP(podName, podNsName, config)
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

func getPodIP(podName string, podNSName string, config *rest.Config) (string, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}
	// namespaces, err := clientset.CoreV1().Namespaces("default").List(context.TODO(), metav1.ListOptions{})
	// // if err != nil {
	// // 	return "", err

	// // }
	// // for _, namespace := range namespaces.Items {
	pods, err := clientset.CoreV1().Pods(podNSName).List(context.TODO(), metav1.ListOptions{})

	for _, pod := range pods.Items {
		if pod.Name == podName {
			return pod.Status.PodIP, nil
		}
	}
	// }
	return "", errors.New("Cann't find the pod for given pod name")

}
