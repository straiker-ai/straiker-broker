// Package provider recognises a model-provider API call from its method, path and body: Anthropic Messages, OpenAI
// Chat Completions and OpenAI Responses, wherever they are served (the provider's own host, Azure, Vertex, an
// in-house gateway). Anything else is not a model call, and the guard lets it through unchecked.
package provider

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Kind is a model API.
type Kind string

const (
	None              Kind = ""
	AnthropicMessages Kind = "anthropic_messages"
	OpenAIChat        Kind = "openai_chat"
	OpenAIResponses   Kind = "openai_responses"
)

// Call is a recognised model call.
type Call struct {
	Kind   Kind
	Model  string
	Stream bool
	// Unreadable is a POST to a model path whose body isn't JSON (compressed, say): Kind is None, but it is a model
	// call the guard can't inspect.
	Unreadable bool
}

// Classify recognises a model call, or returns Kind None. The path decides the API, and the body must have its
// shape: a path alone (a GET, a count_tokens, an Assistants thread message) is not a model call.
func Classify(method, path string, body []byte) Call {
	if !strings.EqualFold(method, "POST") || len(body) == 0 {
		return Call{}
	}
	path = strings.TrimSuffix(path, "/")
	var kind Kind
	switch {
	case strings.HasSuffix(path, "/messages") || vertexAnthropic(path):
		kind = AnthropicMessages
	case strings.HasSuffix(path, "/chat/completions"):
		kind = OpenAIChat
	case strings.HasSuffix(path, "/responses"):
		kind = OpenAIResponses
	default:
		return Call{}
	}
	var b struct {
		Model    json.RawMessage `json:"model"`
		Messages json.RawMessage `json:"messages"`
		Input    json.RawMessage `json:"input"`
		Stream   json.RawMessage `json:"stream"`
	}
	if json.Unmarshal(body, &b) != nil {
		return Call{Unreadable: true} // a model path, but a body that isn't JSON (compressed, say): not inspectable
	}
	switch kind {
	case AnthropicMessages, OpenAIChat:
		if !isArray(b.Messages) {
			return Call{}
		}
	case OpenAIResponses:
		if !isArray(b.Input) && !isString(b.Input) {
			return Call{}
		}
	}
	c := Call{Kind: kind, Stream: bytes.Equal(b.Stream, []byte("true"))}
	_ = json.Unmarshal(b.Model, &c.Model)
	if c.Model == "" && kind == AnthropicMessages {
		c.Model = vertexModel(path)
	}
	return c
}

// vertexAnthropic is Vertex AI's Anthropic endpoint: .../publishers/anthropic/models/<model>:streamRawPredict.
func vertexAnthropic(path string) bool {
	return strings.Contains(path, "/publishers/anthropic/models/") &&
		(strings.HasSuffix(path, ":rawPredict") || strings.HasSuffix(path, ":streamRawPredict"))
}

func vertexModel(path string) string {
	_, rest, ok := strings.Cut(path, "/publishers/anthropic/models/")
	if !ok {
		return ""
	}
	model, _, _ := strings.Cut(rest, ":")
	return model
}

func isArray(raw json.RawMessage) bool  { return len(raw) > 0 && raw[0] == '[' }
func isString(raw json.RawMessage) bool { return len(raw) > 0 && raw[0] == '"' }
