package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// maxSession is the longest session name Defend takes.
const maxSession = 256

// Session names the conversation a model call belongs to, from its body, for a client that sends no session header:
// the call's prompt_cache_key when it has one, or a fingerprint of how the conversation opens (its system prompt and
// first user message, as text), which every later call in that conversation repeats. Empty when neither is there.
func Session(kind Kind, body []byte) string {
	var b struct {
		PromptCacheKey string            `json:"prompt_cache_key"`
		System         json.RawMessage   `json:"system"`
		Instructions   json.RawMessage   `json:"instructions"`
		Messages       []json.RawMessage `json:"messages"`
		Input          json.RawMessage   `json:"input"`
	}
	if kind == None || json.Unmarshal(body, &b) != nil {
		return ""
	}
	if k := strings.TrimSpace(b.PromptCacheKey); k != "" && len(k) <= maxSession {
		return k
	}
	var system []string
	var first string
	switch kind {
	case AnthropicMessages:
		system = append(system, text(b.System))
		first = firstUser(b.Messages, nil)
	case OpenAIChat:
		first = firstUser(b.Messages, &system)
	case OpenAIResponses:
		system = append(system, text(b.Instructions))
		if isString(b.Input) {
			first = text(b.Input)
		} else {
			var items []json.RawMessage
			_ = json.Unmarshal(b.Input, &items)
			first = firstUser(items, &system)
		}
	}
	if first == "" {
		return ""
	}
	h := sha256.Sum256([]byte(string(kind) + "\x00" + strings.Join(system, "\x00") + "\x00" + first))
	return "conv-" + hex.EncodeToString(h[:16])
}

// firstUser is the text of the first user message; system and developer messages before it go to system.
func firstUser(messages []json.RawMessage, system *[]string) string {
	for _, raw := range messages {
		var m struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		switch m.Role {
		case "user":
			return text(m.Content)
		case "system", "developer":
			if system != nil {
				*system = append(*system, text(m.Content))
			}
		}
	}
	return ""
}

// text is a content value's text: a string, or each part's text and nested content (a tool result's), with cache
// markers and other fields left out.
func text(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p.Text != "" {
			out = append(out, p.Text)
		}
		if t := text(p.Content); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

// Newest is the text a request adds to the conversation: every message after the model last spoke (the user's turn,
// a tool's result, anything a client appends), leaving out system and developer messages. Empty when there is none.
func Newest(kind Kind, body []byte) string {
	var b struct {
		Messages []json.RawMessage `json:"messages"`
		Input    json.RawMessage   `json:"input"`
	}
	if kind == None || json.Unmarshal(body, &b) != nil {
		return ""
	}
	items := b.Messages
	if kind == OpenAIResponses {
		if isString(b.Input) {
			return text(b.Input)
		}
		items = nil
		_ = json.Unmarshal(b.Input, &items)
	}
	type message struct {
		Role    string          `json:"role"`
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
		Output  json.RawMessage `json:"output"`
	}
	start, last := 0, -1
	for i, raw := range items {
		var m message
		if json.Unmarshal(raw, &m) == nil && (m.Role == "assistant" || m.Type == "function_call") {
			start, last = i+1, i
		}
	}
	if start == len(items) && last >= 0 {
		// The last message is the assistant's (a prefill the model continues): what's new is the turn before it.
		start = 0
		for i, raw := range items[:last] {
			var m message
			if json.Unmarshal(raw, &m) == nil && (m.Role == "assistant" || m.Type == "function_call") {
				start = i + 1
			}
		}
	}
	var out []string
	for _, raw := range items[start:] {
		var m message
		if json.Unmarshal(raw, &m) != nil || m.Role == "system" || m.Role == "developer" {
			continue
		}
		if t := strings.TrimSpace(text(m.Content) + "\n" + text(m.Output)); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}
