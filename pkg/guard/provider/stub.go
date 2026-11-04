package provider

import (
	"encoding/json"
	"strings"
)

// stubMaxTokens bounds the model's answer to a stub: the notice and nothing more.
const stubMaxTokens = 256

// Stub is a request of call's kind and model that asks the model to answer with notice, word for word, and carries
// nothing of the original but the model and streaming flags. The agent gets an ordinary answer, so a block doesn't
// end its run. Nil when the original isn't a model call the guard can rewrite.
func Stub(call Call, original []byte, notice string) []byte {
	var o struct {
		Model         json.RawMessage `json:"model"`
		Stream        json.RawMessage `json:"stream"`
		StreamOptions json.RawMessage `json:"stream_options"`
	}
	if call.Kind == None || json.Unmarshal(original, &o) != nil {
		return nil
	}
	ask := "Reply with exactly the following text and nothing else, without quoting it:\n\n" +
		strings.TrimSpace(notice)
	body := map[string]any{}
	if len(o.Model) > 0 {
		body["model"] = o.Model
	}
	if len(o.Stream) > 0 {
		body["stream"] = o.Stream
	}
	switch call.Kind {
	case AnthropicMessages:
		body["max_tokens"] = stubMaxTokens
		body["messages"] = []map[string]string{{"role": "user", "content": ask}}
	case OpenAIChat:
		body["max_tokens"] = stubMaxTokens
		body["messages"] = []map[string]string{{"role": "user", "content": ask}}
		if len(o.StreamOptions) > 0 {
			body["stream_options"] = o.StreamOptions
		}
	case OpenAIResponses:
		body["max_output_tokens"] = stubMaxTokens
		body["input"] = ask
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	return out
}
