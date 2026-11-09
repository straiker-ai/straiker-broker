package provider

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		want                     Call
	}{
		{"anthropic", "POST", "/v1/messages", `{"model":"claude-sonnet-4-5","max_tokens":10,"stream":true,"messages":[{"role":"user","content":"hi"}]}`,
			Call{Kind: AnthropicMessages, Model: "claude-sonnet-4-5", Stream: true}},
		{"anthropic, trailing slash", "POST", "/v1/messages/", `{"model":"m","messages":[]}`, Call{Kind: AnthropicMessages, Model: "m", Stream: false}},
		{"vertex anthropic", "POST", "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5:streamRawPredict",
			`{"anthropic_version":"vertex-2023-10-16","messages":[{"role":"user","content":"hi"}],"stream":true}`,
			Call{Kind: AnthropicMessages, Model: "claude-sonnet-4-5", Stream: true}},
		{"openai chat", "POST", "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}`,
			Call{Kind: OpenAIChat, Model: "gpt-5", Stream: false}},
		{"azure chat", "POST", "/openai/deployments/gpt5/chat/completions", `{"messages":[{"role":"user","content":"hi"}],"stream":true}`,
			Call{Kind: OpenAIChat, Model: "", Stream: true}},
		{"responses, list input", "POST", "/v1/responses", `{"model":"gpt-5","input":[{"role":"user","content":"hi"}],"stream":true}`,
			Call{Kind: OpenAIResponses, Model: "gpt-5", Stream: true}},
		{"responses, string input", "POST", "/v1/responses", `{"model":"gpt-5","input":"hi"}`, Call{Kind: OpenAIResponses, Model: "gpt-5", Stream: false}},
		{"a GET", "GET", "/v1/messages", `{"messages":[]}`, Call{}},
		{"count_tokens", "POST", "/v1/messages/count_tokens", `{"model":"m","messages":[]}`, Call{}},
		{"an Assistants thread message", "POST", "/v1/threads/t1/messages", `{"role":"user","content":"hi"}`, Call{}},
		{"messages not a list", "POST", "/v1/messages", `{"messages":"hi"}`, Call{}},
		{"responses without input", "POST", "/v1/responses", `{"model":"gpt-5"}`, Call{}},
		{"not JSON", "POST", "/v1/chat/completions", `messages=hi`, Call{Unreadable: true}},
		{"a compressed body", "POST", "/v1/responses", "\x1f\x8b\x08\x00", Call{Unreadable: true}},
		{"no body", "POST", "/v1/chat/completions", ``, Call{}},
		{"another API", "POST", "/v1/embeddings", `{"model":"e","input":"hi"}`, Call{}},
		{"a model that is not a string", "POST", "/v1/messages", `{"model":7,"messages":[]}`, Call{Kind: AnthropicMessages, Model: "", Stream: false}},
	}
	for _, c := range cases {
		if got := Classify(c.method, c.path, []byte(c.body)); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}
