// Package suite defines adversarial test cases and loads them from JSON.
//
// A suite is data, not code: adding an attack means editing a JSON file, never
// recompiling. That makes validation the important half of this package. A
// suite that loads but is wrong would produce a report that is confidently
// wrong, which is worse than no report at all.
package suite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// SupportedVersion is the only suite_version this build understands.
const SupportedVersion = "1"

// Suite is one file of test cases, as it appears on disk.
type Suite struct {
	Version     string `json:"suite_version"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Cases       []Case `json:"cases"`
}

// Case is a single attack: what to send, and how to tell whether it worked.
type Case struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Severity  string   `json:"severity"`
	OWASP     string   `json:"owasp"`
	Prompt    string   `json:"prompt"`
	Detector  Detector `json:"detector"`
	Rationale string   `json:"rationale"`
}

// Detector says which detector judges the response, plus its configuration.
// Not every field applies to every type; validate enforces which are required.
type Detector struct {
	Type          string   `json:"type"`
	Values        []string `json:"values,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	Pattern       string   `json:"pattern,omitempty"`
}

// The allowed sets. Slices rather than maps so error messages list them in a
// stable, readable order.
var (
	Categories = []string{"prompt_injection", "hidden_context_exposure", "sensitive_data_disclosure"}
	Severities = []string{"critical", "high", "medium", "low"}
)

// detectorRules maps each known detector type to a check of its configuration.
//
// suite may not import detect (spec §5.1), so this table is the suite's own
// record of which detector types exist. When M5 builds the detect registry, a
// test in runner should assert the two agree, so they cannot drift silently.
var detectorRules = map[string]func(Detector) error{
	"contains_any": func(d Detector) error {
		if len(d.Values) == 0 {
			return fmt.Errorf("detector contains_any needs at least one entry in values: %w", ErrMissingField)
		}
		if slices.Contains(d.Values, "") {
			// An empty needle matches every response, so the case would always fail.
			return fmt.Errorf("detector contains_any has an empty string in values: %w", ErrInvalidDetector)
		}
		return nil
	},
	"regex": func(d Detector) error {
		if d.Pattern == "" {
			return fmt.Errorf("detector regex needs a pattern: %w", ErrMissingField)
		}
		if _, err := regexp.Compile(d.Pattern); err != nil {
			return fmt.Errorf("detector regex pattern does not compile: %v: %w", err, ErrInvalidDetector)
		}
		return nil
	},
	"canary_leak":    func(Detector) error { return nil },
	"refusal_absent": func(Detector) error { return nil },
}

// Sentinel errors. Callers and tests match on these with errors.Is; the
// wrapped message carries the human-readable detail.
var (
	ErrRead            = errors.New("cannot read suite")
	ErrMalformed       = errors.New("suite is not valid JSON")
	ErrInvalid         = errors.New("suite failed validation")
	ErrMissingField    = errors.New("required field missing")
	ErrUnknownValue    = errors.New("value not in allowed set")
	ErrDuplicateID     = errors.New("duplicate case id")
	ErrInvalidDetector = errors.New("invalid detector configuration")
)

// Load reads, decodes, and validates the suite at path.
//
// Every error wraps exactly one of ErrRead, ErrMalformed, or ErrInvalid, so a
// caller can tell "file missing" from "file broken" from "file wrong".
func Load(path string) (*Suite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrRead, path, err)
	}

	var s Suite
	dec := json.NewDecoder(bytes.NewReader(data))
	// A typo such as "pattren" would otherwise be silently dropped, and a
	// misspelled optional field like "case_sensitiv" would never be noticed.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", ErrMalformed, path, describeDecodeError(data, err))
	}

	// Decode reads one JSON value and stops. Anything after the suite object,
	// such as a second pasted object, would be silently dropped and its cases
	// would never run. So the next token must be end of input: dec.More() is
	// not enough, because it treats a stray '}' or ']' as a clean ending.
	end := dec.InputOffset()
	if _, err := dec.Token(); err != io.EOF {
		line, col := position(data, end)
		return nil, fmt.Errorf("%w: %s: line %d, column %d: unexpected content after the suite object", ErrMalformed, path, line, col)
	}

	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Validate checks the suite and every case, and reports all problems at once
// rather than stopping at the first. Fixing a suite one error per run is
// miserable.
//
// The returned error wraps ErrInvalid and each individual problem, so
// errors.Is works for both the general and the specific sentinel.
func (s *Suite) Validate() error {
	var problems []error

	if s.Version != SupportedVersion {
		problems = append(problems, fmt.Errorf("suite_version %q is not supported (want %q): %w", s.Version, SupportedVersion, ErrUnknownValue))
	}
	if s.Name == "" {
		problems = append(problems, fmt.Errorf("suite name is empty: %w", ErrMissingField))
	}
	if len(s.Cases) == 0 {
		problems = append(problems, fmt.Errorf("suite has no cases: %w", ErrMissingField))
	}

	seen := make(map[string]int) // case id -> index of first occurrence
	for i, c := range s.Cases {
		label := caseLabel(i, c.ID)

		if c.ID != "" {
			if first, dup := seen[c.ID]; dup {
				problems = append(problems, fmt.Errorf("%s: id already used by case #%d: %w", label, first+1, ErrDuplicateID))
			} else {
				seen[c.ID] = i
			}
		}

		for _, err := range c.validate() {
			problems = append(problems, fmt.Errorf("%s: %w", label, err))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w (%d problems):\n%w", ErrInvalid, len(problems), errors.Join(problems...))
}

// validate returns every problem with a single case, without the case label;
// Suite.Validate adds that.
func (c Case) validate() []error {
	var problems []error

	if c.ID == "" {
		problems = append(problems, fmt.Errorf("id is empty: %w", ErrMissingField))
	}
	if !slices.Contains(Categories, c.Category) {
		problems = append(problems, fmt.Errorf("category %q not in %v: %w", c.Category, Categories, ErrUnknownValue))
	}
	if !slices.Contains(Severities, c.Severity) {
		problems = append(problems, fmt.Errorf("severity %q not in %v: %w", c.Severity, Severities, ErrUnknownValue))
	}
	if strings.TrimSpace(c.Prompt) == "" {
		problems = append(problems, fmt.Errorf("prompt is empty: %w", ErrMissingField))
	}

	rule, known := detectorRules[c.Detector.Type]
	switch {
	case c.Detector.Type == "":
		problems = append(problems, fmt.Errorf("detector type is empty: %w", ErrMissingField))
	case !known:
		problems = append(problems, fmt.Errorf("detector type %q not in %v: %w", c.Detector.Type, DetectorTypes(), ErrUnknownValue))
	default:
		if err := rule(c.Detector); err != nil {
			problems = append(problems, err)
		}
	}

	return problems
}

// DetectorTypes returns the known detector types, sorted.
func DetectorTypes() []string {
	types := make([]string, 0, len(detectorRules))
	for t := range detectorRules {
		types = append(types, t)
	}
	slices.Sort(types)
	return types
}

// caseLabel names a case in an error message. Cases are numbered from 1
// because that is how a person counts them in the file.
func caseLabel(i int, id string) string {
	if id == "" {
		return fmt.Sprintf("case #%d (no id)", i+1)
	}
	return fmt.Sprintf("case %s", id)
}

// describeDecodeError turns encoding/json's byte offsets into line and column,
// which is what an editor can jump to.
func describeDecodeError(data []byte, err error) string {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		line, col := position(data, syntax.Offset)
		return fmt.Sprintf("line %d, column %d: %v", line, col, err)
	case errors.As(err, &typ):
		line, col := position(data, typ.Offset)
		return fmt.Sprintf("line %d, column %d: field %q should be %s, got JSON %s", line, col, typ.Field, typ.Type, typ.Value)
	case errors.Is(err, io.ErrUnexpectedEOF):
		line, col := position(data, int64(len(data)))
		return fmt.Sprintf("line %d, column %d: file ends before the JSON is complete", line, col)
	default:
		return err.Error()
	}
}

// position converts a byte offset into a 1-based line and column.
func position(data []byte, offset int64) (line, col int) {
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	before := data[:offset]
	line = bytes.Count(before, []byte("\n")) + 1
	col = int(offset) - bytes.LastIndexByte(before, '\n')
	return line, col
}
