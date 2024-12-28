package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestInitContainerStates(t *testing.T) {
	csm := &ContainerStateManager{
		stateByPID: make(map[int]*ContainerState),
		mu:         sync.RWMutex{},
	}
	csm.InitContainerStates()
	t.Logf("Number of container states: %d", len(csm.stateByPID))
	for _, state := range csm.stateByPID {
		t.Logf("State: %+v", state)
	}
}

func TestStartPodInformer(t *testing.T) {
	// 创建一个带有上下文取消功能的 Context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建 ContainerStateManager 实例
	sm := NewContainerStateManager()

	// 创建一个日志记录器
	logger := log.New(log.Writer(), "test: ", log.LstdFlags)
	sm.InitContainerStates()

	// 启动 Pod Informer
	sm.StartPodInformer(ctx, logger)

	// 等待 Informer 的缓存同步
	// 在生产代码中，Informer 的内部缓存需要时间与 API Server 同步
	time.Sleep(1 * time.Second)

	// 等待事件处理完成
	// 由于 Informer 是异步处理事件的，需要等待一段时间
	time.Sleep(100 * time.Second)
}

func TestGetPodAndContainerInfoFromContainerd(t *testing.T) {

	contianerID := "12f182e87a9b2b9e719ff59f2749df8e3a863c5a6a0a5cce118670a7303c6609"

	podName, ns, containerName, err := getPodAndContainerInfoFromContainerd(contianerID)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	fmt.Println("Pod Name: ", podName)
	fmt.Println("Namespace: ", ns)
	fmt.Println("Container Name: ", containerName)

}

// 定义通用的 HTTP GET 请求
func httpGet(url string, headers map[string]string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	// 添加 Headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send GET request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET request failed with status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

// 定义通用的 HTTP POST 请求
func httpPost(url string, headers map[string]string, payload map[string]interface{}) ([]byte, error) {
	client := &http.Client{}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}

	// 添加 Headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	// 确保添加 Content-Type
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST request failed with status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

// 获取 Profile ID
func getProfileID() (string, error) {
	profileURL := "http://localhost:8080/api/application/profile" // 替换为实际 URL
	body, err := httpGet(profileURL, headers)
	if err != nil {
		return "", fmt.Errorf("failed to get profile ID: %w", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode profile response: %w", err)
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if id, ok := data["id"].(string); ok {
			return id, nil
		}
	}

	return "", fmt.Errorf("profile ID not found in response")
}

// 获取 Chat ID
func getChatID(profileID string) (string, error) {
	chatOpenURL := fmt.Sprintf("http://localhost:8080/api/application/%s/chat/open", profileID) // 替换为实际 URL
	body, err := httpGet(chatOpenURL, headers)
	if err != nil {
		return "", fmt.Errorf("failed to get chat ID: %w", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode chat response: %w", err)
	}

	if data, ok := response["data"].(string); ok {
		return data, nil
	}

	return "", fmt.Errorf("chat ID not found in response")
}

// 发送聊天消息
func sendChatMessage(chatID string, payload map[string]interface{}) (string, error) {
	chatMessageURL := fmt.Sprintf("http://localhost:8080/api/application/chat_message/%s", chatID)
	body, err := httpPost(chatMessageURL, headers, payload)
	if err != nil {
		return "", fmt.Errorf("failed to send chat message: %w", err)
	}
	// 打印完整的响应体
	// 打印完整的响应体
	fmt.Printf("Chat message response: %s\n", string(body)) // Add this line
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode chat message response: %w", err)
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if content, ok := data["content"].(string); ok {
			return content, nil
		}
	}

	return "", fmt.Errorf("content not found in chat message response")
}

// 主测试函数
func TestChatFlow(t *testing.T) {
	message := "你好"
	reChat := false
	stream := false

	// 获取 Profile ID
	profileID, err := getProfileID()
	if err != nil {
		t.Fatalf("Failed to get profile ID: %v", err)
	}
	t.Logf("Profile ID: %s", profileID)

	// 获取 Chat ID
	chatID, err := getChatID(profileID)
	if err != nil {
		t.Fatalf("Failed to get chat ID: %v", err)
	}
	t.Logf("Chat ID: %s", chatID)

	// 准备消息 payload
	payload := map[string]interface{}{
		"message": message,
		"re_chat": reChat,
		"stream":  stream,
	}

	// 发送聊天消息
	content, err := sendChatMessage(chatID, payload)
	if err != nil {
		t.Fatalf("Failed to send chat message: %v", err)
	}
	t.Logf("Chat response content: %s", content)
}
