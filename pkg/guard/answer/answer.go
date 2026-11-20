// Package answer reassembles a model's answer as its response body arrives in pieces, and says when it is worth a
// check: as soon as a tool call the client will run is complete (before the piece that completes it is released),
// and at the end for anything no check has covered. It understands the streams of Anthropic Messages, OpenAI Chat
// Completions and OpenAI Responses; a non-streamed answer is checked once, whole.
package answer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/straiker-ai/straiker-broker/pkg/guard/provider"
	"github.com/straiker-ai/straiker-broker/pkg/guard/secrets"
)

// ErrTooLarge is an answer beyond the tracker's bound; it keeps nothing more.
var ErrTooLarge = errors.New("answer exceeds the inspection bound")

// clientTools are the Responses items the client runs; server-side tools (web search, remote MCP) have run already.
var clientTools = map[string]bool{
	"function_call": true, "custom_tool_call": true, "local_shell_call": true,
	"shell_call": true, "apply_patch_call": true, "computer_call": true,
}

// Tracker follows one response.
type Tracker struct {
	kind provider.Kind
	sse  bool
	max  int

	buf    []byte // the answer so far, verbatim, for the check
	parsed int    // where the next unparsed line starts
	data   []byte // the current event's data lines
	blocks map[int]string

	parts map[string]*strings.Builder // a stream's text and tool arguments, rebuilt from its deltas, per block
	order []string                    // parts in the order they started

	completed int  // content blocks (or choices, or output items) completed so far
	covered   int  // how many of them a check has seen
	checked   bool // a check has run
	toolDone  bool // a client tool call completed since the last check
}

// New tracks an answer of kind; sse is a text/event-stream body. max bounds the bytes kept.
func New(kind provider.Kind, sse bool, max int) *Tracker {
	return &Tracker{kind: kind, sse: sse, max: max, blocks: map[int]string{}, parts: map[string]*strings.Builder{}}
}

// Feed takes the next piece of the body.
func (t *Tracker) Feed(p []byte) error {
	if len(t.buf)+len(p) > t.max {
		t.buf, t.data, t.parts, t.order = nil, nil, map[string]*strings.Builder{}, nil
		return ErrTooLarge
	}
	t.buf = append(t.buf, p...)
	if t.sse {
		t.scan()
	}
	return nil
}

// Due reports whether to check the answer now: a tool call the client will run is complete, or the body ended
// with content no check has seen.
func (t *Tracker) Due(end bool) bool {
	if len(bytes.TrimSpace(t.buf)) == 0 {
		return false
	}
	return t.toolDone || (end && (!t.checked || t.completed > t.covered))
}

// Checked records a check of everything fed so far.
func (t *Tracker) Checked() {
	t.checked, t.covered, t.toolDone = true, t.completed, false
}

// Text is the answer so far, verbatim.
func (t *Tracker) Text() string { return string(t.buf) }

// Content is the answer's text and tool arguments so far, decoded: for a stream, rebuilt from its deltas (a key split
// across deltas is whole here); otherwise the JSON body's string values. What the guard's own credential check scans.
func (t *Tracker) Content() string {
	if !t.sse {
		return strings.Join(secrets.Strings(t.buf), "\n")
	}
	out := make([]string, 0, len(t.order))
	for _, k := range t.order {
		out = append(out, t.parts[k].String())
	}
	return strings.Join(out, "\n")
}

func (t *Tracker) add(key, text string) {
	if text == "" {
		return
	}
	b, ok := t.parts[key]
	if !ok {
		b = &strings.Builder{}
		t.parts[key] = b
		t.order = append(t.order, key)
	}
	b.WriteString(text)
}

// deltas adds what one event's deltas carry: text, thinking and tool arguments.
func (t *Tracker) deltas(data []byte) {
	switch t.kind {
	case provider.AnthropicMessages:
		var e struct {
			Index int `json:"index"`
			Delta struct {
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				Thinking    string `json:"thinking"`
			} `json:"delta"`
		}
		if json.Unmarshal(data, &e) == nil {
			k := fmt.Sprintf("b%d", e.Index)
			t.add(k, e.Delta.Text+e.Delta.PartialJSON+e.Delta.Thinking)
		}
	case provider.OpenAIChat:
		var e struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(data, &e) == nil {
			for _, c := range e.Choices {
				if c.Delta.Content != nil {
					t.add(fmt.Sprintf("c%d", c.Index), *c.Delta.Content)
				}
				for _, tc := range c.Delta.ToolCalls {
					t.add(fmt.Sprintf("c%d.t%d", c.Index, tc.Index), tc.Function.Arguments)
				}
			}
		}
	case provider.OpenAIResponses:
		var e struct {
			Type        string `json:"type"`
			OutputIndex int    `json:"output_index"`
			Delta       any    `json:"delta"`
		}
		if json.Unmarshal(data, &e) == nil && strings.HasSuffix(e.Type, ".delta") {
			if d, ok := e.Delta.(string); ok {
				t.add(fmt.Sprintf("o%d", e.OutputIndex), d)
			}
		}
	}
}

// scan reads complete lines; a blank line ends an event.
func (t *Tracker) scan() {
	for {
		i := bytes.IndexByte(t.buf[t.parsed:], '\n')
		if i < 0 {
			return
		}
		line := bytes.TrimSuffix(t.buf[t.parsed:t.parsed+i], []byte("\r"))
		t.parsed += i + 1
		switch {
		case len(line) == 0:
			if len(t.data) > 0 {
				t.event(t.data)
			}
			t.data = t.data[:0]
		case bytes.HasPrefix(line, []byte("data:")):
			v := bytes.TrimPrefix(line[len("data:"):], []byte(" "))
			if len(t.data) > 0 {
				t.data = append(t.data, '\n')
			}
			t.data = append(t.data, v...)
		}
	}
}

// event notes what one event completes.
func (t *Tracker) event(data []byte) {
	var e struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
		} `json:"content_block"`
		Item struct {
			Type string `json:"type"`
		} `json:"item"`
		Choices []struct {
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(data, &e) != nil { // [DONE], a comment, or a malformed event
		return
	}
	t.deltas(data)
	switch t.kind {
	case provider.AnthropicMessages:
		switch e.Type {
		case "content_block_start":
			t.blocks[e.Index] = e.ContentBlock.Type
		case "content_block_stop":
			t.completed++
			if t.blocks[e.Index] == "tool_use" {
				t.toolDone = true
			}
			delete(t.blocks, e.Index)
		}
	case provider.OpenAIChat:
		for _, c := range e.Choices {
			if c.FinishReason == nil || *c.FinishReason == "" {
				continue
			}
			t.completed++
			if *c.FinishReason == "tool_calls" || *c.FinishReason == "function_call" {
				t.toolDone = true
			}
		}
	case provider.OpenAIResponses:
		if e.Type == "response.output_item.done" {
			t.completed++
			if clientTools[e.Item.Type] {
				t.toolDone = true
			}
		}
	}
}
