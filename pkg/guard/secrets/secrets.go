// Package secrets finds credentials whose format proves what they are: the guard's own check for when Straiker gives
// no verdict. The families are argus's api_key table (argus/domain/patterns.py) less its two looser ones (JWTs and
// generic prefixed tokens), which need Defend's judgement rather than a pattern's.
package secrets

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// maxScan bounds the text scanned, like argus's detector.
const maxScan = 64 << 10

// keyEnd is where a credential must end; RE2 has no lookahead, so it consumes the next character or the end.
const keyEnd = `(?:[^A-Za-z0-9_-]|$)`

type family struct {
	name    string
	markers []string
	re      *regexp.Regexp
}

// fam compiles a family as (credential)(end): the end is kept when the credential is redacted.
func fam(name string, markers []string, body string, framed bool) family {
	end := "()"
	if !framed {
		end = "(" + keyEnd + ")"
	}
	return family{name, markers, regexp.MustCompile("(" + body + ")" + end)}
}

var families = []family{
	fam("aws_access_key_id", []string{"AKIA", "ASIA", "ABIA", "ACCA"}, `\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, false),
	fam("github_token", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, `\bgh[pousr]_[A-Za-z0-9]{36,255}`, false),
	fam("github_fine_grained", []string{"github_pat_"}, `\bgithub_pat_[A-Za-z0-9_]{50,255}`, false),
	fam("openai_scoped", []string{"sk-proj-", "sk-svcacct-", "sk-admin-"}, `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,255}`, false),
	fam("anthropic", []string{"sk-ant-"}, `\bsk-ant-[A-Za-z0-9_-]{20,255}`, false),
	fam("openai_legacy", []string{"sk-"}, `\bsk-[A-Za-z0-9]{32,255}`, false),
	fam("gitlab_pat", []string{"glpat-"}, `\bglpat-[A-Za-z0-9_-]{20,255}`, false),
	fam("slack_token", []string{"xox"}, `\bxox[abeoprs]-[A-Za-z0-9-]{10,255}`, false),
	fam("google_api_key", []string{"AIza"}, `\bAIza[A-Za-z0-9_-]{35}`, false),
	fam("huggingface", []string{"hf_"}, `\bhf_[A-Za-z0-9]{34,255}`, false),
	fam("npm_token", []string{"npm_"}, `\bnpm_[A-Za-z0-9]{36,255}`, false),
	fam("stripe_live", []string{"sk_live_", "rk_live_"}, `\b[sr]k_live_[A-Za-z0-9]{10,255}`, false),
	fam("digitalocean", []string{"dop_v1_"}, `\bdop_v1_[a-f0-9]{64}`, false),
	fam("sendgrid", []string{"SG."}, `\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,64}`, false),
	fam("pem_private_key", []string{"PRIVATE KEY"}, `-----BEGIN (?:[A-Z][A-Z0-9]* )?PRIVATE KEY-----`, true),
}

// Find is the family of the first credential in text, or "".
func Find(text string) string {
	if len(text) > maxScan {
		text = text[:maxScan]
	}
	for _, f := range families {
		if !hasAny(text, f.markers) {
			continue
		}
		if f.re.MatchString(text) {
			return f.name
		}
	}
	return ""
}

func hasAny(text string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// pemBlock is a whole PEM private key, through its END line, or to the end of the text when that is missing: masking
// only the BEGIN line would leave the key itself. (?s) lets it span the key's lines.
var pemBlock = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z][A-Z0-9]* )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z][A-Z0-9]* )?PRIVATE KEY-----|$)`)

// Redaction is what replaces a credential: its family, never any of its characters.
func Redaction(family string) string { return "[REDACTED by Straiker: " + family + "]" }

// Mask replaces every credential in text with its Redaction, and names the families it replaced. It scans all of
// text (a request body, up to the gateway's 4 MiB), not only the first maxScan bytes. The redaction holds no quote
// or backslash, so masking a JSON body leaves it valid JSON.
func Mask(text string) (string, []string) {
	var found []string
	for _, f := range families {
		if !hasAny(text, f.markers) {
			continue
		}
		if !f.re.MatchString(text) {
			continue
		}
		found = append(found, f.name)
		if f.name == "pem_private_key" {
			text = pemBlock.ReplaceAllString(text, Redaction(f.name))
			continue
		}
		text = f.re.ReplaceAllString(text, Redaction(f.name)+"${2}")
	}
	return text, found
}

// MaskJSON masks every credential in a JSON body's string values, decoded: in the raw JSON an escape such as \n
// would hide a key's start from the pattern, and a PEM key's lines would be escaped. It names the families it
// replaced, and clean is false when a credential is still found after masking (the caller must not send it). A body
// that isn't JSON comes back unchanged, with nothing replaced.
func MaskJSON(body []byte) (masked []byte, families []string, clean bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return body, nil, Find(string(body)) == ""
	}
	seen := map[string]bool{}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			m, f := Mask(t)
			for _, name := range f {
				if !seen[name] {
					seen[name] = true
					families = append(families, name)
				}
			}
			return m
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case map[string]any:
			for k, val := range t {
				t[k] = walk(val)
			}
		}
		return x
	}
	v = walk(v)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return body, nil, false
	}
	masked = bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	return masked, families, Find(strings.Join(Strings(masked), "\n")) == ""
}

// Strings are a JSON document's string values, decoded, in document order for arrays (map order otherwise); nil
// when it isn't JSON. What the guard's own check scans, so escapes don't hide a key.
func Strings(doc []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(doc))
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		if s, ok := tok.(string); ok {
			out = append(out, s)
		}
	}
}
