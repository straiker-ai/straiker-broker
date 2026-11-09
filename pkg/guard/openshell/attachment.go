package openshell

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/types/known/structpb"
)

// Attachment is the guard's config on one policy attachment (network_middlewares.<name>.config). Both keys are
// optional and default to true:
//
//	config:
//	  request: true    # check model requests before they leave the sandbox
//	  response: true   # check model answers before the sandbox gets them
type Attachment struct {
	Request  bool
	Response bool
}

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
		b, ok := v.GetKind().(*structpb.Value_BoolValue)
		switch {
		case k != "request" && k != "response":
			return a, fmt.Errorf("unknown key %q: the guard's config takes request and response (true or false)", k)
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
