package openshell

import (
	"fmt"
	"regexp"
	"sort"

	"google.golang.org/protobuf/types/known/structpb"
)

// Attachment is the guard's config on one policy attachment (network_middlewares.<name>.config). Every key is
// optional; request and response default to true:
//
//	config:
//	  request: true    # check model requests before they leave the sandbox
//	  response: true   # check model answers before the sandbox gets them
//	  ascend_copy_of: <sandbox id>   # set by Straiker Ascend on a test copy: the agent it copies
type Attachment struct {
	Request  bool
	Response bool
	// CopyOf marks an Ascend test copy: the sandbox id of the agent it was made from. The guard passes a copy's
	// calls unchecked, so red-team traffic neither mints an agent per copy nor lands in the agent's history. Only
	// the policy's author sets it: a sandbox can't change its own policy.
	CopyOf string
}

// copyOfKey is the attachment key Ascend sets on a copy; its value is an OpenShell sandbox id (a UUID).
const copyOfKey = "ascend_copy_of"

var sandboxIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ParseAttachment reads and validates an attachment's config; nil or empty is the default.
func ParseAttachment(s *structpb.Struct) (Attachment, error) {
	a := Attachment{Request: true, Response: true}
	if s == nil {
		return a, nil
	}
	keys := make([]string, 0, len(s.GetFields()))
	for k := range s.GetFields() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := s.GetFields()[k]
		if k == copyOfKey {
			id, ok := v.GetKind().(*structpb.Value_StringValue)
			if !ok || !sandboxIDRE.MatchString(id.StringValue) {
				return a, fmt.Errorf("%s must be the copied sandbox's id (a lowercase UUID)", copyOfKey)
			}
			a.CopyOf = id.StringValue
			continue
		}
		b, ok := v.GetKind().(*structpb.Value_BoolValue)
		switch {
		case k != "request" && k != "response":
			return a, fmt.Errorf("unknown key %q: the guard's config takes request and response (true or false) and %s",
				k, copyOfKey)
		case !ok:
			return a, fmt.Errorf("%s must be true or false", k)
		case k == "request":
			a.Request = b.BoolValue
		default:
			a.Response = b.BoolValue
		}
	}
	if !a.Request && !a.Response {
		return a, fmt.Errorf("request and response are both false, so the guard would check nothing: remove the attachment instead")
	}
	return a, nil
}
