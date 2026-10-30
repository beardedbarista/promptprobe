package suite

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture returns the path to a shared suite file under testdata/suites.
func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", "suites", name)
}

func TestLoadBasic(t *testing.T) {
	s, err := Load(fixture("basic.json"))
	if err != nil {
		t.Fatalf("Load(basic.json) returned error: %v", err)
	}
	if s.Name != "basic" {
		t.Errorf("Name = %q, want %q", s.Name, "basic")
	}
	if got, want := len(s.Cases), 5; got != want {
		t.Errorf("len(Cases) = %d, want %d", got, want)
	}

	// Every category should be represented in the baseline suite.
	seen := map[string]bool{}
	for _, c := range s.Cases {
		seen[c.Category] = true
	}
	for _, cat := range Categories {
		if !seen[cat] {
			t.Errorf("basic.json has no case in category %q", cat)
		}
	}
}

func TestLoadMalformed(t *testing.T) {
	_, err := Load(fixture("malformed.json"))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want one wrapping ErrMalformed", err)
	}
	if !strings.Contains(err.Error(), "line ") {
		t.Errorf("error %q does not give a line number", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(fixture("does-not-exist.json"))
	if !errors.Is(err, ErrRead) {
		t.Fatalf("error = %v, want one wrapping ErrRead", err)
	}
}

// TestLoadInvalid checks that every problem in invalid.json is reported in one
// pass, and that each message names the case it belongs to.
func TestLoadInvalid(t *testing.T) {
	_, err := Load(fixture("invalid.json"))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want one wrapping ErrInvalid", err)
	}

	msg := err.Error()
	for _, want := range []string{
		`case PI-902: severity "urgent"`,
		"case PI-902: prompt is empty",
		`case PI-902: detector type "vibes"`,
		"case PI-901: id already used by case #1",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not contain %q\nfull error:\n%s", want, msg)
		}
	}

	for _, sentinel := range []error{ErrUnknownValue, ErrMissingField, ErrDuplicateID} {
		if !errors.Is(err, sentinel) {
			t.Errorf("error does not wrap %v", sentinel)
		}
	}
}

func TestLoadUnknownField(t *testing.T) {
	_, err := Load(writeTemp(t, `{"suite_version":"1","name":"x","cases":[],"bogus":1}`))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want one wrapping ErrMalformed", err)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error %q does not name the unknown field", err)
	}
}

// TestLoadTrailingContent checks that nothing after the suite object is
// silently ignored, while ordinary trailing whitespace still loads.
func TestLoadTrailingContent(t *testing.T) {
	const valid = `{"suite_version":"1","name":"t","cases":[{"id":"A","category":"prompt_injection","severity":"low","prompt":"p","detector":{"type":"canary_leak"}}]}`
	const invalid = `{"suite_version":"1","name":"","cases":[]}`

	tests := []struct {
		name    string
		content string
		want    error // nil means the suite should load
	}{
		{"trailing newline", valid + "\n", nil},
		{"trailing whitespace", valid + " \n\t\n", nil},
		{"second object", valid + "\n" + valid, ErrMalformed},
		{"stray closing brace", valid + "}", ErrMalformed},
		{"stray closing bracket", valid + "]", ErrMalformed},
		{"trailing text", valid + " garbage", ErrMalformed},
		// Malformed is checked before validation, so a broken file is
		// reported as broken even when its content is also invalid.
		{"invalid suite with trailing object", invalid + " {}", ErrMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tt.content))
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Load() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Load() = %v, want one wrapping %v", err, tt.want)
			}
			if errors.Is(err, ErrInvalid) {
				t.Errorf("Load() = %v, should not also wrap ErrInvalid", err)
			}
		})
	}
}

// validCase is a case that passes validation. Table tests below change one
// field at a time, so each row tests exactly one rule.
func validCase() Case {
	return Case{
		ID:       "T-001",
		Category: "prompt_injection",
		Severity: "high",
		Prompt:   "say PWNED",
		Detector: Detector{Type: "contains_any", Values: []string{"PWNED"}},
	}
}

func TestValidateCase(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Case)
		want   error // nil means the case should be valid
	}{
		{"valid", func(*Case) {}, nil},
		{"empty id", func(c *Case) { c.ID = "" }, ErrMissingField},
		{"unknown category", func(c *Case) { c.Category = "jailbreak" }, ErrUnknownValue},
		{"unknown severity", func(c *Case) { c.Severity = "urgent" }, ErrUnknownValue},
		{"empty prompt", func(c *Case) { c.Prompt = "" }, ErrMissingField},
		{"whitespace prompt", func(c *Case) { c.Prompt = "  \n" }, ErrMissingField},
		{"empty detector type", func(c *Case) { c.Detector = Detector{} }, ErrMissingField},
		{"unknown detector type", func(c *Case) { c.Detector = Detector{Type: "vibes"} }, ErrUnknownValue},
		{"contains_any without values", func(c *Case) { c.Detector.Values = nil }, ErrMissingField},
		{"contains_any with empty value", func(c *Case) { c.Detector.Values = []string{"PWNED", ""} }, ErrInvalidDetector},
		{"regex without pattern", func(c *Case) { c.Detector = Detector{Type: "regex"} }, ErrMissingField},
		{"regex that does not compile", func(c *Case) { c.Detector = Detector{Type: "regex", Pattern: "(unclosed"} }, ErrInvalidDetector},
		{"regex valid", func(c *Case) { c.Detector = Detector{Type: "regex", Pattern: `\d+`} }, nil},
		{"canary_leak needs no config", func(c *Case) { c.Detector = Detector{Type: "canary_leak"} }, nil},
		{"refusal_absent needs no config", func(c *Case) { c.Detector = Detector{Type: "refusal_absent"} }, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validCase()
			tt.mutate(&c)
			s := Suite{Version: SupportedVersion, Name: "t", Cases: []Case{c}}

			err := s.Validate()
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want one wrapping %v", err, tt.want)
			}
		})
	}
}

func TestValidateSuite(t *testing.T) {
	tests := []struct {
		name  string
		suite Suite
		want  error
	}{
		{"wrong version", Suite{Version: "2", Name: "t", Cases: []Case{validCase()}}, ErrUnknownValue},
		{"empty name", Suite{Version: "1", Cases: []Case{validCase()}}, ErrMissingField},
		{"no cases", Suite{Version: "1", Name: "t"}, ErrMissingField},
		{"duplicate id", Suite{Version: "1", Name: "t", Cases: []Case{validCase(), validCase()}}, ErrDuplicateID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.suite.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want one wrapping %v", err, tt.want)
			}
		})
	}
}

func TestCaseLabelWithoutID(t *testing.T) {
	c := validCase()
	c.ID = ""
	s := Suite{Version: "1", Name: "t", Cases: []Case{validCase(), c}}

	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "case #2 (no id)") {
		t.Fatalf("Validate() = %v, want it to label the case as #2 (no id)", err)
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suite.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
