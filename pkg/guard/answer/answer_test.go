package answer

import (
	"errors"
	"strings"
	"testing"

	"github.com/straiker-ai/straiker-broker/pkg/guard/provider"
	"github.com/straiker-ai/straiker-broker/pkg/guard/secrets"
)

func sse(events ...string) string {
	var b strings.Builder
	for _, e := range events {
		b.WriteString("data: " + e + "\n\n")
	}
	return b.String()
}

var anthropicToolTurn = "event: message_start\n" + sse(
	`{"type":"message_start","message":{"id":"msg_1","role":"assistant","content":[]}}`,
	`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Cleaning up."}}`,
	`{"type":"content_block_stop","index":0}`,
	`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}`,
	`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"rm -rf"}}`,
	`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":" /\"}"}}`,
	`{"type":"content_block_stop","index":1}`,
	`{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
	`{"type":"message_stop"}`,
)

// feed splits body into pieces of n bytes and reports at which pieces a check is due.
func feed(t *testing.T, tr *Tracker, body string, n int) []int {
	t.Helper()
	var due []int
	for i := 0; i*n < len(body); i++ {
		end := min((i+1)*n, len(body))
		if err := tr.Feed([]byte(body[i*n : end])); err != nil {
			t.Fatal(err)
		}
		if tr.Due(end == len(body)) {
			due = append(due, i)
			tr.Checked()
		}
	}
	return due
}

func TestAnAnthropicToolCallIsDueInThePieceThatCompletesIt(t *testing.T) {
	for _, n := range []int{7, 64, 333, len(anthropicToolTurn)} {
		tr := New(provider.AnthropicMessages, true, 1<<20)
		due := feed(t, tr, anthropicToolTurn, n)
		stop := strings.Index(anthropicToolTurn, `{"type":"content_block_stop","index":1}`)
		eol := stop + strings.Index(anthropicToolTurn[stop:], "\n\n") + 1 // the event ends at its blank line
		if len(due) != 1 || due[0] != eol/n {
			t.Errorf("pieces of %d: due at %v, want only at piece %d", n, due, eol/n)
		}
		if tr.Text() != anthropicToolTurn {
			t.Errorf("pieces of %d: the answer is not kept verbatim", n)
		}
	}
}

func TestAnAnswerWithoutToolsIsCheckedOnceAtTheEnd(t *testing.T) {
	body := sse(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
		`{"type":"content_block_stop","index":0}`, `{"type":"message_stop"}`)
	tr := New(provider.AnthropicMessages, true, 1<<20)
	if due := feed(t, tr, body, 40); len(due) != 1 || due[0] != (len(body)-1)/40 {
		t.Fatalf("due at %v", due)
	}
}

func TestTextAfterAToolCallGetsItsOwnCheck(t *testing.T) {
	body := anthropicToolTurn[:strings.Index(anthropicToolTurn, "data: {\"type\":\"message_delta\"")] + sse(
		`{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_stop","index":2}`, `{"type":"message_stop"}`)
	cut := strings.Index(body, `{"type":"content_block_start","index":2`)
	tr := New(provider.AnthropicMessages, true, 1<<20)
	for i, piece := range []string{body[:cut], body[cut:]} {
		if err := tr.Feed([]byte(piece)); err != nil {
			t.Fatal(err)
		}
		if !tr.Due(i == 1) {
			t.Fatalf("piece %d: want a check for the tool call, then for the trailing text", i)
		}
		tr.Checked()
	}
}

func TestOpenAIChatToolCallsAreDueAtTheirFinishReason(t *testing.T) {
	body := sse(
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}`,
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":\"ls\"}"}}]},"finish_reason":null}]}`,
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`{"object":"chat.completion.chunk","choices":[],"usage":{"total_tokens":9}}`,
	) + "data: [DONE]\n\n"
	tr := New(provider.OpenAIChat, true, 1<<20)
	finish := strings.Index(body, `"finish_reason":"tool_calls"`)
	eol := finish + strings.Index(body[finish:], "\n\n") + 1
	if due := feed(t, tr, body, 50); len(due) != 1 || due[0] != eol/50 {
		t.Fatalf("due at %v, want %d", due, eol/50)
	}
}

func TestOpenAIResponsesClientToolCallsAreDueWhenTheirItemIsDone(t *testing.T) {
	body := "event: response.output_item.done\n" + sse(
		`{"type":"response.output_item.done","output_index":0,"item":{"type":"web_search_call","id":"ws_1","status":"completed"}}`,
	) + "event: response.output_item.done\n" + sse(
		`{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"c1","name":"bash","arguments":"{}"}}`,
	) + "event: response.completed\n" + sse(`{"type":"response.completed","response":{"status":"completed"}}`)
	tr := New(provider.OpenAIResponses, true, 1<<20)
	first := strings.Index(body, "web_search_call")
	if due := feed(t, tr, body, first+10); len(due) != 1 {
		t.Fatalf("due at %v: a server-side tool is not due, the function call is, and nothing after it", due)
	}
}

func TestCRLFStreamsAreRead(t *testing.T) {
	body := strings.ReplaceAll(anthropicToolTurn, "\n", "\r\n")
	if due := feed(t, New(provider.AnthropicMessages, true, 1<<20), body, 100); len(due) != 1 {
		t.Fatalf("due at %v", due)
	}
}

func TestAWholeAnswerIsCheckedOnlyAtItsEnd(t *testing.T) {
	body := `{"id":"msg_1","type":"message","content":[{"type":"tool_use","id":"t","name":"bash","input":{}}]}`
	tr := New(provider.AnthropicMessages, false, 1<<20)
	if due := feed(t, tr, body, 10); len(due) != 1 || due[0] != (len(body)-1)/10 {
		t.Fatalf("due at %v", due)
	}
	if New(provider.OpenAIChat, false, 10).Due(true) {
		t.Fatal("an empty answer is never due")
	}
}

func TestAnAnswerOverTheBoundIsDropped(t *testing.T) {
	tr := New(provider.AnthropicMessages, true, 100)
	if err := tr.Feed(make([]byte, 60)); err != nil {
		t.Fatal(err)
	}
	if err := tr.Feed(make([]byte, 60)); !errors.Is(err, ErrTooLarge) || tr.Text() != "" {
		t.Fatalf("%v, kept %d bytes", err, len(tr.Text()))
	}
}

func TestAKeySplitAcrossDeltasIsWholeInTheContent(t *testing.T) {
	anthropic := sse(
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"bash","input":{}}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"curl -H AKIAIOSF"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"ODNN7EXAMPLE x\"}"}}`,
		`{"type":"content_block_stop","index":0}`,
	)
	chat := sse(
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash","arguments":"{\"c\":\"AKIAIOSF"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"name":"ls","arguments":"{}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ODNN7EXAMPLE\"}"}}]}}]}`,
	)
	responses := sse(
		`{"type":"response.function_call_arguments.delta","output_index":2,"delta":"{\"c\":\"AKIAIOSF"}`,
		`{"type":"response.function_call_arguments.delta","output_index":2,"delta":"ODNN7EXAMPLE\"}"}`,
	)
	for name, c := range map[string]struct {
		kind provider.Kind
		body string
	}{"anthropic": {provider.AnthropicMessages, anthropic}, "chat (interleaved calls)": {provider.OpenAIChat, chat},
		"responses": {provider.OpenAIResponses, responses}} {
		tr := New(c.kind, true, 1<<20)
		feed(t, tr, c.body, 7)
		if secrets.Find(tr.Text()) != "" || secrets.Find(tr.Content()) != "aws_access_key_id" {
			t.Errorf("%s: the raw stream hides the key, the content shows it: %q", name, tr.Content())
		}
	}
	whole := New(provider.OpenAIChat, false, 1<<20)
	feed(t, whole, `{"choices":[{"message":{"content":"x\nAKIAIOSFODNN7EXAMPLE"}}]}`, 1000)
	if secrets.Find(whole.Content()) != "aws_access_key_id" {
		t.Errorf("a whole answer's decoded strings: %q", whole.Content())
	}
}
