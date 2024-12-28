package loki

const LokiURL = "http://localhost:3100/loki/api/v1/push"

// LokiPushPayload 表示要发送给 Loki 的日志数据
type LokiPushPayload struct {
	Streams []LokiStream `json:"streams"`
}

// LokiStream 表示单个日志流
type LokiStream struct {
	Stream map[string]string `json:"stream"` // 标签
	Values [][]string        `json:"values"` // 日志条目
}
