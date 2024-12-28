package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"cacapture/user/chatbot"
	"cacapture/user/loki"
)

// 定义 API Key
const apiKey = "application-6965a429294bcc8c19f47a840f95b73e" // 替换为实际 API Key
const baseURL = "http://localhost:8080"

// 定义 headers
var headers = map[string]string{
	"accept":        "application/json",
	"Authorization": apiKey,
}

// 容器状态管理器
type ContainerStateManager struct {
	mu         sync.RWMutex
	stateByPID map[int]*ContainerState
	clientset  *kubernetes.Clientset

	// Prometheus metrics
	containerCount          prometheus.Gauge
	containerSyscallCounter *prometheus.GaugeVec
	containerPIDGauge       *prometheus.GaugeVec

	// Contact with LLM
	llm_client *chatbot.LLMClient
}

func GetCurrentNodeName() string {
	// 从环境变量中获取当前节点名称（适用于在 Pod 中运行的程序）
	return os.Getenv("NODE_NAME")
}

func initK8sClient() *kubernetes.Clientset {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Failed to create in-cluster config: %v", err)

		// 尝试加载本地 kubeconfig 文件
		kubeconfig := os.Getenv("KUBECONFIG") // 从环境变量中读取 kubeconfig 路径
		if kubeconfig == "" {
			// 如果未设置 KUBECONFIG 环境变量，使用默认路径（通常为 ~/.kube/config）
			kubeconfig = clientcmd.RecommendedHomeFile
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Failed to load kubeconfig: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	return clientset
}
func GetNodePods(clientset *kubernetes.Clientset, nodeName string) ([]v1.Pod, error) {
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods on node %s: %v", nodeName, err)
	}
	return pods.Items, nil
}

// 提取实际的 container ID
func ExtractContainerID(fullContainerID string) (string, error) {
	parts := strings.Split(fullContainerID, "://")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid container ID format: %s", fullContainerID)
	}
	return parts[1], nil
}

// 从 Containerd 获取容器的 PID
func GetContainerPID(containerID string) (int, error) {
	// 连接到 containerd 的默认 socket
	client, err := containerd.New("/run/containerd/containerd.sock") // 默认路径
	if err != nil {
		return 0, fmt.Errorf("failed to connect to containerd: %v", err)
	}
	defer client.Close()

	// 创建上下文，在 `k8s.io` 命名空间中操作
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	// 加载容器
	container, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		return 0, fmt.Errorf("failed to load container %s: %v", containerID, err)
	}

	// 获取容器的任务
	task, err := container.Task(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to get task for container %s: %v", containerID, err)
	}

	// 从任务中直接获取 PID
	pid := int(task.Pid())
	if pid == 0 {
		return 0, fmt.Errorf("task for container %s has no valid PID", containerID)
	}

	return pid, nil
}

// 从 Containerd 获取容器的 Pod 名称、Namespace 和容器名称
func getPodAndContainerInfoFromContainerd(containerID string) (string, string, string, error) {
	// 创建 containerd 客户端
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create containerd client: %w", err)
	}
	defer client.Close()

	// 设置 namespace 为 k8s.io (Kubernetes 默认使用的 namespace)
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	// 加载容器
	container, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to load container: %w", err)
	}

	// 获取容器的 labels
	labels, err := container.Labels(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get container labels: %w", err)
	}

	// 提取 Pod 名称、Namespace 和容器名称
	podName := labels["io.kubernetes.pod.name"]
	namespace := labels["io.kubernetes.pod.namespace"]
	containerName := labels["io.kubernetes.container.name"]

	// 校验结果
	if podName == "" || namespace == "" || containerName == "" {
		return "", "", "", fmt.Errorf("failed to find required Kubernetes labels in container metadata")
	}

	return podName, namespace, containerName, nil
}

// 创建新的状态管理器
func NewContainerStateManager() *ContainerStateManager {
	csm := &ContainerStateManager{
		stateByPID: make(map[int]*ContainerState),
		containerCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "container_count",
			Help: "The current number of containers being managed",
		}),
		containerSyscallCounter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "container_syscall_count",
				Help: "The current number of syscalls made by containers, labeled by container ID and syscall type",
			},
			[]string{"container_name", "pod_name", "namespace", "syscall"}, // 定义标签：容器 ID 和系统调用类型
		),
		containerPIDGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "container_pid",
				Help: "The PID of containers being managed, labeled by container ID",
			},
			[]string{"container_name", "pod_name", "namespace"},
		),
		llm_client: chatbot.NewLLMClient(baseURL, headers),
	}

	// Register metrics with Prometheus
	prometheus.MustRegister(csm.containerCount)
	prometheus.MustRegister(csm.containerSyscallCounter)
	prometheus.MustRegister(csm.containerPIDGauge)

	return csm
}

// 获取clientset
func (sm *ContainerStateManager) GetClientset() *kubernetes.Clientset {
	if sm.clientset == nil {
		sm.clientset = initK8sClient()
	}
	return sm.clientset
}

// 根据 PID 获取容器状态
func (sm *ContainerStateManager) GetContainerStateByPID(pid int) (*ContainerState, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	state, ok := sm.stateByPID[pid]
	return state, ok
}

// 更新容器状态
func (sm *ContainerStateManager) UpdateContainerState(pid int, state *ContainerState) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.stateByPID[pid] = state
	sm.UpdatePrometheusData(state)
}

// 更新prometheus数据
func (sm *ContainerStateManager) UpdatePrometheusData(state *ContainerState) {
	for syscall, count := range state.SyscallCount {
		sm.containerSyscallCounter.WithLabelValues(state.ContainerName, state.PodName, state.Namespace, syscall).Set(float64(count))
	}
}

func (sm *ContainerStateManager) UpdateLokiData(containerStates map[string]string) error {
	// 构造多个日志流（streams）
	var streams []loki.LokiStream

	for containerName, llmResponse := range containerStates {
		// 生成时间戳
		timestamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)

		// 构造日志条目
		values := [][]string{
			{timestamp, llmResponse},
		}

		// 构造日志流
		stream := loki.LokiStream{
			Stream: map[string]string{
				"job":       "container_manager",
				"container": containerName,
			},
			Values: values,
		}

		streams = append(streams, stream)
	}

	// 构造请求的 Payload
	payload := loki.LokiPushPayload{
		Streams: streams,
	}

	// 将 Payload 转换为 JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Loki payload: %v", err)
	}

	// 发送 HTTP 请求到 Loki
	resp, err := http.Post("http://localhost:3100/loki/api/v1/push", "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to send logs to Loki: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response from Loki: %s, body: %s", resp.Status, string(body))
	}

	fmt.Println("All logs sent to Loki successfully!")
	return nil
}
func (sm *ContainerStateManager) InitContainerStatesFromPods(pods []v1.Pod) {
	for _, pod := range pods {
		for _, container := range pod.Status.ContainerStatuses {
			// 提取实际的 container ID
			containerID, err := ExtractContainerID(container.ContainerID)
			if err != nil {
				log.Printf("Failed to extract container ID for pod %s, container %s: %v", pod.Name, container.Name, err)
				continue
			}

			// 获取容器的 PID
			pid, err := GetContainerPID(containerID)
			if err != nil {
				log.Printf("Failed to get PID for container %s: %v", containerID, err)
				pid = 0 // 如果获取 PID 失败，设置为 0
			}

			// 创建并更新容器状态
			state := &ContainerState{
				ContainerID:   containerID,
				PID:           pid,
				SyscallCount:  map[string]int{},
				PodName:       pod.Name,
				Namespace:     pod.Namespace,
				ContainerName: container.Name,
			}
			sm.UpdateContainerState(pid, state)
			log.Printf("Initialized container state: Pod=%s, Container=%s, PID=%d", pod.Name, container.Name, pid)
		}
	}
}

// 初始化容器状态

func (sm *ContainerStateManager) InitContainerStates() {
	// 初始化 Kubernetes 客户端
	clientset := sm.GetClientset()

	// 获取当前节点名称
	nodeName := GetCurrentNodeName()
	log.Printf("Current node: %s", nodeName)

	// 获取当前节点上的pod
	pods, err := GetNodePods(clientset, nodeName)
	for _, pod := range pods {
		log.Printf("Pod: %s", pod.Name)
	}
	if err != nil {
		log.Fatalf("Failed to get pods on node %s: %v", nodeName, err)
	}

	// 初始化容器状态
	sm.InitContainerStatesFromPods(pods)

}

func (sm *ContainerStateManager) HandlePodAdded(pod *v1.Pod) {
	for _, container := range pod.Status.ContainerStatuses {
		if container.ContainerID == "" {
			log.Printf("ContainerID is empty for Pod %s, Container %s. Retrying...", pod.Name, container.Name)
			go func() {
				time.Sleep(2 * time.Second) // 等待 2 秒后重试
				updatedPod, err := sm.GetClientset().CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
				if err != nil {
					log.Printf("Failed to get updated pod %s: %v", pod.Name, err)
					return
				}
				sm.HandlePodAdded(updatedPod) // 递归调用自己
			}()
			return
		}
		containerID, err := ExtractContainerID(container.ContainerID)

		if err != nil {
			log.Printf("Failed to extract container ID for pod %s, container %s: %v", pod.Name, container.Name, err)
			continue
		}

		pid, err := GetContainerPID(containerID)
		if err != nil {
			log.Printf("Failed to get PID for container %s: %v", containerID, err)
			pid = 0
		}

		state := &ContainerState{
			ContainerID:   containerID,
			PID:           pid,
			SyscallCount:  map[string]int{},
			PodName:       pod.Name,
			Namespace:     pod.Namespace,
			ContainerName: container.Name,
		}
		sm.UpdateContainerState(pid, state)
		log.Printf("Container added: Pod=%s, Container=%s, PID=%d", pod.Name, container.Name, pid)
		sm.containerCount.Inc()
		sm.containerPIDGauge.WithLabelValues(state.ContainerName, state.PodName, state.Namespace).Set(float64(pid))

	}
}

func (sm *ContainerStateManager) HandlePodDeleted(pod *v1.Pod) {
	for _, container := range pod.Status.ContainerStatuses {
		containerID, err := ExtractContainerID(container.ContainerID)
		if err != nil {
			log.Printf("Failed to extract container ID for pod %s, container %s: %v", pod.Name, container.Name, err)
			continue
		}

		sm.mu.Lock()
		for pid, state := range sm.stateByPID {
			if state.ContainerID == containerID {
				delete(sm.stateByPID, pid)
				log.Printf("Container deleted: Pod=%s, Container=%s, PID=%d", pod.Name, container.Name, pid)
				for syscall := range state.SyscallCount {
					sm.containerSyscallCounter.DeleteLabelValues(state.ContainerName, state.PodName, state.Namespace, syscall) // 删除对应的系统调用计数
				}
				break
			}
		}
		sm.mu.Unlock()
		sm.containerPIDGauge.DeleteLabelValues(container.Name, pod.Name, pod.Namespace)
		sm.containerCount.Dec()
	}
}

func (sm *ContainerStateManager) StartPodInformer(ctx context.Context, logger *log.Logger) {
	clientset := sm.GetClientset()
	factory := informers.NewSharedInformerFactory(clientset, time.Minute)
	podInformer := factory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				logger.Println("Failed to cast object to Pod")
				return
			}
			sm.HandlePodAdded(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, ok1 := oldObj.(*v1.Pod)
			newPod, ok2 := newObj.(*v1.Pod)
			if !ok1 || !ok2 {
				logger.Println("Failed to cast object to Pod")
				return
			}

			// 检查容器状态是否从空更新为非空
			if len(oldPod.Status.ContainerStatuses) == 0 && len(newPod.Status.ContainerStatuses) > 0 {
				logger.Printf("Pod updated with containers: %s/%s", newPod.Namespace, newPod.Name)
				sm.HandlePodAdded(newPod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				logger.Println("Failed to cast object to Pod")
				return
			}
			sm.HandlePodDeleted(pod)
		},
	})

	go podInformer.Run(ctx.Done())
}

// DescribeAllContainerStates 将所有容器状态描述整合为一条自然语言消息
func (sm *ContainerStateManager) DescribeAllContainerStates() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	descriptions := []string{}
	for _, state := range sm.stateByPID {
		description := fmt.Sprintf(
			"容器 \"%s\" (ID: %s) 位于命名空间 \"%s\" 中，属于 Pod \"%s\"。当前系统调用统计如下：",
			state.ContainerName, state.ContainerID, state.Namespace, state.PodName,
		)

		// 添加系统调用统计信息
		syscallDescriptions := []string{}
		for syscall, count := range state.SyscallCount {
			syscallDescriptions = append(syscallDescriptions, fmt.Sprintf("%s 为 %d 次", syscall, count))
		}

		// 拼接单个容器的描述
		description += strings.Join(syscallDescriptions, ",") + "。"
		descriptions = append(descriptions, description)

	}

	// 拼接问题
	quesion := "在这些容器系统调用中，是否存在危险的系统调用？如果有请指出哪些容器，以及危险的系统调用。如果没有请直接回答没有"
	// 指定返回格式
	format := "你必须以这种格式回答：\n{容器1名:对于容器1的危险系统调用及其原因,容器2名:对于容器2的危险系统调用及其原因,...}\n 既你必须返回一个json格式的字符串,其中键为容器名,这个是个string,值为对应容器的危险系统调用及其原因,这个也是一个string,除此之外不要回答任何信息"
	descriptions = append(descriptions, quesion)
	descriptions = append(descriptions, format)
	cot_string := "例如：" + chatbot.COT_String
	descriptions = append(descriptions, cot_string)
	// 拼接所有容器的描述
	return strings.Join(descriptions, "\n")
}

// MonitorContainersWithLLM 定期发送所有容器状态到 LLM
func (sm *ContainerStateManager) MonitorContainersWithLLM() {
	ticker := time.NewTicker(1 * time.Minute) // 每 1 分钟执行一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 构造所有容器状态的描述
			description := sm.DescribeAllContainerStates()

			// 构建发送给 LLM 的 Payload
			payload := map[string]interface{}{
				"message": description,
				"re_chat": false,
				"stream":  false,
			}

			profileID, err := sm.llm_client.GetProfileID()
			chatID, err := sm.llm_client.GetChatID(profileID)
			if err != nil {
				fmt.Printf("Failed to get chat ID: %v\n", err)
				continue
			}
			// 调用 sendChatMessage 函数，发送给大模型
			response, err := sm.llm_client.SendChatMessage(chatID, payload)
			if err != nil {
				fmt.Printf("Failed to send container states to LLM: %v\n", err)
				continue
			}

			// 处理 LLM 的返回结果
			fmt.Printf("LLM response: %s\n", response)
			containerLLMResponse, err := ParseLLMResponse(response)
			if err != nil {
				fmt.Printf("Failed to parse LLM response: %v\n", err)
			}
			err = sm.UpdateLokiData(containerLLMResponse)
			if err != nil {
				fmt.Printf("Failed to update Loki data: %v\n", err)
			} else {
				fmt.Printf("Update Loki data success")
			}
			// 根据返回结果采取相应行动
			// TODO: 增加报警或日志记录
		}
	}
}

// ParseLLMResponse 解析 LLM 的返回结果到每个容器状态
func ParseLLMResponse(response string) (map[string]string, error) {
	// 预处理
	// 删除```json```
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimSuffix(response, "```")
	// 解析 LLM 返回的 JSON 数据
	var data map[string]interface{}
	err := json.Unmarshal([]byte(response), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM response: %v, perhaps the LLM response isn't Json string", err)
	}

	// 提取每个容器的 LLM 返回结果
	containerLLMResponse := make(map[string]string)
	for container, result := range data {
		resultStr, ok := result.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected LLM result type for container %s: %T", container, result)
		}
		containerLLMResponse[container] = resultStr
	}

	return containerLLMResponse, nil
}
