package provider

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStubKeepsOnlyTheModelAndStreamingAndAsksForTheNotice(t *testing.T) {
	original := `{"model":"claude-haiku-5-5","stream":true,"stream_options":{"include_usage":true},` +
		`"tools":[{"type":"function"}],"messages":[{"role":"system","content":"sys"},{"role":"user","content":"SECRET-7f3a"}]}`
	call := Classify("POST", "/v1/chat/completions", []byte(original))
	out := Stub(call, []byte(original), "Blocked by Straiker Defend.")
	if strings.Contains(string(out), "SECRET-7f3a") || strings.Contains(string(out), "tools") || strings.Contains(string(out), "sys") {
		t.Fatalf("the stub carries the original: %s", out)
	}
	var b struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role, Content string
		} `json:"messages"`
		StreamOptions map[string]bool `json:"stream_options"`
	}
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if b.Model != "claude-haiku-5-5" || !b.Stream || !b.StreamOptions["include_usage"] || len(b.Messages) != 1 ||
		!strings.Contains(b.Messages[0].Content, "Blocked by Straiker Defend.") {
		t.Fatalf("%+v", b)
	}
	if again := Classify("POST", "/v1/chat/completions", out); again.Kind != OpenAIChat {
		t.Fatal("the stub is not a model call of the same kind")
	}
}

func TestStubIsEachAPIsShape(t *testing.T) {
	anthropic := `{"model":"m","max_tokens":1000,"messages":[{"role":"user","content":"x"}]}`
	responses := `{"model":"m","input":"x"}`
	if out := Stub(Classify("POST", "/v1/messages", []byte(anthropic)), []byte(anthropic), "n"); Classify("POST", "/v1/messages", out).Kind != AnthropicMessages {
		t.Fatalf("anthropic: %s", out)
	}
	if out := Stub(Classify("POST", "/v1/responses", []byte(responses)), []byte(responses), "n"); Classify("POST", "/v1/responses", out).Kind != OpenAIResponses {
		t.Fatalf("responses: %s", out)
	}
	if Stub(Call{}, []byte(`{}`), "n") != nil {
		t.Fatal("a stub for a call that is not a model call")
	}
}
