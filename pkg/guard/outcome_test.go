package guard

import (
	"errors"
	"testing"

	"github.com/straiker-ai/straiker-broker/pkg/guard/detect"
)

func TestErrorKinds(t *testing.T) {
	for err, want := range map[error]string{
		detect.ErrTimeout:                  "timeout",
		errors.Join(detect.ErrUnreachable): "unreachable",
		&detect.StatusError{Code: 503}:     "http_503",
		errors.New("odd"):                  "invalid_reply",
	} {
		if got := errorKind(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	if got := clip("héllo", 2); got != "h" {
		t.Errorf("clip cuts on a character boundary: %q", got)
	}
}
