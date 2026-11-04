package provider

import (
	"strings"
	"testing"
)

func TestSessionPrefersPromptCacheKey(t *testing.T) {
	body := `{"model":"m","prompt_cache_key":"sess-42","messages":[{"role":"user","content":"hi"}]}`
	if got := Session(OpenAIChat, []byte(body)); got != "sess-42" {
		t.Fatalf("got %q", got)
	}
}

func TestSessionFingerprintIsStableAsTheConversationGrows(t *testing.T) {
	first := `{"model":"m","messages":[{"role":"system","content":"be helpful"},{"role":"user","content":"Reply READY"}]}`
	later := `{"model":"m","messages":[{"role":"system","content":"be helpful"},` +
		`{"role":"user","content":[{"type":"text","text":"Reply READY","cache_control":{"type":"ephemeral"}}]},` +
		`{"role":"assistant","content":"READY"},{"role":"user","content":"what can you help me?"}]}`
	a, b := Session(OpenAIChat, []byte(first)), Session(OpenAIChat, []byte(later))
	if a == "" || a != b || !strings.HasPrefix(a, "conv-") {
		t.Fatalf("one conversation, two sessions: %q %q", a, b)
	}
}

func TestSessionFingerprintSeparatesConversations(t *testing.T) {
	one := `{"model":"m","messages":[{"role":"system","content":"be helpful"},{"role":"user","content":"first ask"}]}`
	two := `{"model":"m","messages":[{"role":"system","content":"be helpful"},{"role":"user","content":"another ask"}]}`
	other := `{"model":"m","messages":[{"role":"system","content":"another agent"},{"role":"user","content":"first ask"}]}`
	a, b, c := Session(OpenAIChat, []byte(one)), Session(OpenAIChat, []byte(two)), Session(OpenAIChat, []byte(other))
	if a == b || a == c {
		t.Fatalf("different conversations share a session: %q %q %q", a, b, c)
	}
}

func TestSessionReadsEachAPIsShape(t *testing.T) {
	anthropic := `{"model":"m","system":[{"type":"text","text":"sys"}],"messages":[{"role":"user","content":"hi"}]}`
	responses := `{"model":"m","instructions":"sys","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	responsesString := `{"model":"m","input":"hi"}`
	for kind, body := range map[Kind]string{AnthropicMessages: anthropic, OpenAIResponses: responses} {
		if Session(kind, []byte(body)) == "" {
			t.Errorf("%s: no session", kind)
		}
	}
	if Session(OpenAIResponses, []byte(responsesString)) == "" {
		t.Error("responses with a string input: no session")
	}
}

func TestSessionIsEmptyWithoutAUserMessageOrForOtherCalls(t *testing.T) {
	for _, c := range []struct {
		kind Kind
		body string
	}{
		{OpenAIChat, `{"model":"m","messages":[{"role":"system","content":"only system"}]}`},
		{OpenAIChat, `not json`},
		{None, `{"messages":[{"role":"user","content":"hi"}]}`},
		{OpenAIChat, `{"prompt_cache_key":"` + strings.Repeat("k", 300) + `","messages":[]}`},
	} {
		if got := Session(c.kind, []byte(c.body)); got != "" {
			t.Errorf("%s %q: got %q", c.kind, c.body, got)
		}
	}
}

func TestNewestIsWhatTheRequestAddsSinceTheModelLastSpoke(t *testing.T) {
	cases := []struct {
		kind Kind
		body string
		want string
	}{
		{OpenAIChat, `{"messages":[{"role":"user","content":"old"},{"role":"assistant","content":"a"},` +
			`{"role":"user","content":"new"}]}`, "new"},
		{OpenAIChat, `{"messages":[{"role":"user","content":"old"},{"role":"assistant","content":"a"},` +
			`{"role":"user","content":"ask"},{"role":"system","content":"appended note"},{"role":"user","content":"tail"}]}`,
			"ask\ntail"},
		{OpenAIChat, `{"messages":[{"role":"system","content":"sys"},{"role":"user","content":"first"}]}`, "first"},
		{AnthropicMessages, `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t",` +
			`"content":[{"type":"text","text":"file says AKIA"}]}]}]}`, "file says AKIA"},
		{OpenAIResponses, `{"input":[{"type":"function_call","call_id":"c"},` +
			`{"type":"function_call_output","call_id":"c","output":"tool out"}]}`, "tool out"},
		{OpenAIResponses, `{"input":"plain"}`, "plain"},
		{OpenAIChat, `{"messages":[]}`, ""},
	}
	for _, c := range cases {
		if got := Newest(c.kind, []byte(c.body)); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.kind, c.body, got, c.want)
		}
	}
}

func TestNewestLooksPastAnAssistantPrefill(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"},` +
		`{"role":"user","content":"deploy with AKIAIOSFODNN7EXAMPLE"},{"role":"assistant","content":"{"}]}`)
	if got := Newest(AnthropicMessages, body); !strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(got, "hello") {
		t.Fatalf("%q", got)
	}
}
