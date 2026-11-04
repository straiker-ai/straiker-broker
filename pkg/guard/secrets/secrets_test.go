package secrets

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindsEachFamily(t *testing.T) {
	cases := map[string]string{
		"aws_access_key_id":   "key AKIAABCDEFGHIJKLMNOP here",
		"github_token":        "ghp_" + strings.Repeat("a", 36),
		"github_fine_grained": "github_pat_" + strings.Repeat("b", 60),
		"openai_scoped":       "OPENAI_API_KEY=sk-proj-Ab3dEf5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH2iJ4",
		"anthropic":           "sk-ant-" + strings.Repeat("c", 40),
		"openai_legacy":       "sk-" + strings.Repeat("d", 48),
		"gitlab_pat":          "glpat-" + strings.Repeat("e", 20),
		"slack_token":         "xoxb-1234567890-abcdef",
		"google_api_key":      "AIza" + strings.Repeat("f", 35),
		"huggingface":         "hf_" + strings.Repeat("g", 34),
		"npm_token":           "npm_" + strings.Repeat("h", 36),
		"stripe_live":         "sk_live_" + strings.Repeat("i", 24),
		"digitalocean":        "dop_v1_" + strings.Repeat("a", 64),
		"sendgrid":            "SG." + strings.Repeat("j", 22) + "." + strings.Repeat("k", 43),
		"pem_private_key":     "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
	}
	for want, text := range cases {
		if got := Find(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
}

func TestIgnoresLookalikesAndLooserFamilies(t *testing.T) {
	for _, text := range []string{
		"",
		"just a normal question about sk- prefixes",
		"sk-short",
		"AKIAABCDEFGHIJKLMNOPQ", // 21 characters: not an AWS key id
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWhlcmUtbG9uZw", // a JWT: Defend decides
		"api_" + strings.Repeat("x", 40),                                              // generic prefix: Defend decides
		"pk_live_" + strings.Repeat("p", 24),
	} {
		if got := Find(text); got != "" {
			t.Errorf("%q: got %q", text, got)
		}
	}
}

func TestScanIsBounded(t *testing.T) {
	text := strings.Repeat("x", maxScan) + " AKIAABCDEFGHIJKLMNOP"
	if got := Find(text); got != "" {
		t.Fatalf("scanned past the bound: %q", got)
	}
}

func TestMaskRedactsEveryCredentialAndKeepsJSONValid(t *testing.T) {
	key := "sk-proj-Ab3dEf5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH2iJ4"
	body := `{"messages":[{"role":"user","content":"OPENAI_API_KEY=` + key + `"},` +
		`{"role":"assistant","content":"ok"},{"role":"user","content":"again ` + key + `, and AKIAABCDEFGHIJKLMNOP."}]}`
	masked, found := Mask(body)
	if strings.Contains(masked, key) || strings.Contains(masked, "AKIAABCDEFGHIJKLMNOP") {
		t.Fatalf("a credential survived: %s", masked)
	}
	if len(found) != 2 || Find(masked) != "" {
		t.Fatalf("found %v, still finds %q", found, Find(masked))
	}
	if !strings.Contains(masked, Redaction("aws_access_key_id")+".") || !strings.Contains(masked, `"},{"role":"assistant"`) {
		t.Fatalf("the text around a credential changed: %s", masked)
	}
	var v any
	if err := json.Unmarshal([]byte(masked), &v); err != nil {
		t.Fatalf("masked body is not JSON: %v", err)
	}
}

func TestMaskLeavesCleanTextAlone(t *testing.T) {
	text := `{"messages":[{"role":"user","content":"no secrets here"}]}`
	if masked, found := Mask(text); masked != text || found != nil {
		t.Fatalf("%q %v", masked, found)
	}
}

const pemKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwIa1yV9q3xLkPm\nZ8bQ2TgR7vN4sW1cE6hJ0aYfU5o=\n-----END RSA PRIVATE KEY-----"

func TestMaskJSONRemovesAWholePEMKey(t *testing.T) {
	for name, key := range map[string]string{"whole": pemKey, "no END line": strings.SplitN(pemKey, "-----END", 2)[0]} {
		body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": "here:\n" + key + "\nthanks"}}})
		masked, families, clean := MaskJSON(body)
		if !clean || len(families) != 1 || families[0] != "pem_private_key" {
			t.Fatalf("%s: %v %v", name, families, clean)
		}
		for _, leak := range []string{"MIIEow", "Z8bQ2T", "END RSA"} {
			if strings.Contains(string(masked), leak) {
				t.Errorf("%s: %q survives: %s", name, leak, masked)
			}
		}
		if !json.Valid(masked) || !strings.Contains(string(masked), Redaction("pem_private_key")) {
			t.Errorf("%s: %s", name, masked)
		}
	}
}

func TestMaskJSONSeesAKeyRightAfterAnEscape(t *testing.T) {
	gh := "ghp_" + strings.Repeat("a1B2", 9)
	body, _ := json.Marshal(map[string]any{"input": "token " + gh + "\nAKIAIOSFODNN7EXAMPLE\t<AKIAIOSFODNN7EXAMPLF"})
	masked, families, clean := MaskJSON(body)
	if !clean || len(families) != 2 || strings.Contains(string(masked), "AKIA") || strings.Contains(string(masked), gh) {
		t.Fatalf("%v %v %s", families, clean, masked)
	}
}

func TestMaskJSONIsNotCleanWhenAKeySurvives(t *testing.T) {
	// A key in an object's name isn't masked (only values are), so the body must not be sent as masked.
	body := []byte(`{"AKIAIOSFODNN7EXAMPLE":"x","note":"AKIAIOSFODNN7EXAMPLF"}`)
	if _, _, clean := MaskJSON(body); clean {
		t.Fatal("a body that still carries a key is clean")
	}
}
