package guard

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/straiker-ai/straiker-broker/pkg/guard/detect"
)

// Reason codes a gateway returns to the agent with a denial and records in its logs.
const (
	CodeBlocked     = "straiker_blocked"
	CodeKillswitch  = "straiker_killswitch"
	CodeUnavailable = "straiker_unavailable"
	CodeBusy        = "straiker_guard_busy"
	CodeLocalBlock  = "straiker_local_block"
)

const (
	maxLabelBytes     = 1024
	maxReasonBytes    = 4096
	findingBlock      = "straiker.block"
	findingDetect     = "straiker.detect"
	findingNoAnswer   = "straiker.unavailable"
	findingLocalBlock = "straiker.local_block"
)

// Finding is one thing the guard reports with a decision, for the gateway's logs.
type Finding struct {
	Type     string
	Label    string
	Count    uint32
	Severity string
}

// Outcome is what the guard tells the gateway about one verdict, whichever operation it answers.
type Outcome struct {
	Deny       bool
	Reason     string // a diagnostic for the guard's operator, not shown to the agent
	ReasonCode string
	Findings   []Finding
	Metadata   map[string]string
	// Replace, when set, is the request body to send instead of denying (on_block: replace): the call goes ahead
	// with it, so the agent gets an ordinary answer and its run doesn't end.
	Replace []byte
}

// outcome maps a verdict (or the failure to get one) to the guard's decision. Block denies; detect allows with a
// finding per control; a failure follows the guard's on_straiker_error policy.
func (e *Engine) outcome(v *detect.Verdict, err error) Outcome {
	if err != nil {
		o := Outcome{Reason: clip("Straiker Defend gave no verdict: "+err.Error(), maxReasonBytes),
			Metadata: map[string]string{"straiker_error": errorKind(err)}}
		if e.onError == FailClosed {
			o.Deny, o.ReasonCode = true, CodeUnavailable
		}
		o.Findings = []Finding{{Type: findingNoAnswer, Count: 1, Severity: "info",
			Label: "Straiker Defend gave no verdict; on_straiker_error=" + string(e.onError)}}
		return o
	}
	o := Outcome{Metadata: map[string]string{"straiker_action": string(v.Action)}}
	if v.TurnID != "" {
		o.Metadata["straiker_turn_id"] = v.TurnID
	}
	switch v.Action {
	case detect.Block:
		o.Deny, o.ReasonCode = true, CodeBlocked
		if v.Killswitch {
			o.ReasonCode = CodeKillswitch
		}
		label := v.Message
		if label == "" {
			label = "blocked by Straiker Defend"
		}
		o.Reason = clip("blocked by Straiker Defend: "+strings.Join(v.BlockedBy, ", "), maxReasonBytes)
		o.Findings = append(o.Findings, Finding{Type: findingBlock, Label: clip(label, maxLabelBytes), Count: 1,
			Severity: "high"})
		o.Findings = append(o.Findings, controlFindings(findingBlock, v.BlockedBy, "high")...)
	case detect.Detect:
		o.Findings = controlFindings(findingDetect, v.Controls, "medium")
	}
	return o
}

func controlFindings(typ string, controls []string, severity string) []Finding {
	out := make([]Finding, 0, len(controls))
	for _, c := range controls {
		out = append(out, Finding{Type: typ, Label: clip(c, maxLabelBytes), Count: 1, Severity: severity})
	}
	return out
}

// errorKind is a short, content-free name for a failure, for the gateway's metadata.
func errorKind(err error) string {
	var se *detect.StatusError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("http_%d", se.Code)
	case errors.Is(err, detect.ErrTimeout):
		return "timeout"
	case errors.Is(err, detect.ErrUnreachable):
		return "unreachable"
	}
	return "invalid_reply"
}

// clip cuts s to at most n bytes, on a character boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
