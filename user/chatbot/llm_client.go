package chatbot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const COT_String = `{"kube-apiserver":对于当前列出的所有系统调用，没有直接标识出危险的行为。但如果从潜在风险的角度考虑，
"setsockopt", "socket", 和 "accept4" 可能用于建立网络连接和监听端口，这在某些情况下可能被滥用以进行未经授权的通信或服务暴露。需要进一步监控这些操作的确切用途及其安全性。文件操作中，读取了 "apiserver-etcd-client.crt" 文件 130493 字节，"apiserver-etcd-client.key" 文件 171455 字节，"apiserver-kubelet-client.crt" 文件 32983 字节，"apiserver-kubelet-client.key" 文件 43601 字节，这些操作可能涉及证书和密钥相关信息，需确保文件安全性及访问权限控制,"kube-controller-manager":对于当前列出的所有系统调用，没有直接标识出危险的行为。但如果从潜在风险的角度考虑，“accept4” 可能用于建立网络监听，如果未正确配置可能会导致安全漏洞。需进一步审查其使用场景和安全性。当前未记录到显著的文件操作,"kube-scheduler":对于当前列出的所有系统调用，没有直接标识出危险的行为。但“accept4”可能涉及网络监听功能，若不适当管理可能导致潜在的安全风险,需要详细检查其具体应用场景和是否符合安全策略。当前未记录到显著的文件操作,"etcd":对于当前列出的所有系统调用，没有直接标识出危险的行为。但文件操作中，写入了 "0000000000000001-00000000000176ef.wal" 文件 168117912 字节，写入了 "db" 文件 3212296192 字节，读取了 "server.crt" 文件 5588597 字节，读取了 "server.key" 文件 7766213 字节。这些文件涉及到数据存储、证书和密钥，需确保其完整性及访问权限，防止数据篡改或泄露,"kube-proxy":对于当前列出的所有系统调用，没有直接标识出危险的行为。文件操作中，读取了 "token" 文件 7120 字节，该文件可能涉及认证信息，需确保安全性,"coredns":对于当前列出的所有系统调用，没有直接标识出危险的行为。但文件操作中，读取了 "Corefile" 文件 48109 字节和 38519 字节，读取了 "token" 文件 10691 字节，这些文件可能涉及配置或认证信息，需确保文件的正确性及访问权限控制。}`

// LLMClient 用于与 LLM 服务交互
type LLMClient struct {
	BaseURL string
	Headers map[string]string
}

// NewLLMClient 创建一个新的 LLMClient 实例
func NewLLMClient(baseURL string, headers map[string]string) *LLMClient {
	return &LLMClient{
		BaseURL: baseURL,
		Headers: headers,
	}
}

// HTTP GET 请求
func (c *LLMClient) httpGet(endpoint string) ([]byte, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	// 添加 Headers
	for key, value := range c.Headers {
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

// HTTP POST 请求
func (c *LLMClient) httpPost(endpoint string, payload map[string]interface{}) ([]byte, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}

	// 添加 Headers
	for key, value := range c.Headers {
		req.Header.Set(key, value)
	}
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
func (c *LLMClient) GetProfileID() (string, error) {
	body, err := c.httpGet("/api/application/profile")
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
			fmt.Println("profile id:", id)
		}
	}

	return "", fmt.Errorf("profile ID not found in response")
}

// 获取 Chat ID
func (c *LLMClient) GetChatID(profileID string) (string, error) {
	endpoint := fmt.Sprintf("/api/application/%s/chat/open", profileID)
	body, err := c.httpGet(endpoint)
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
func (c *LLMClient) SendChatMessage(chatID string, payload map[string]interface{}) (string, error) {
	endpoint := fmt.Sprintf("/api/application/chat_message/%s", chatID)
	body, err := c.httpPost(endpoint, payload)
	if err != nil {
		return "", fmt.Errorf("failed to send chat message: %w", err)
	}

	// 打印完整的响应体

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
