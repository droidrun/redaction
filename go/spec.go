package redaction

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// The spec is embedded: a copy of spec/*.json written by tools/sync-spec. Nothing is read from
// disk at run time.
//
//go:embed spec/rules.json spec/keys.json spec/algorithms.json
var specFiles embed.FS

const (
	supportedSpecVersion = 1
	maxMacroDepth        = 8
)

// hashedFiles is the order of the integrity hash (SPEC section 12).
var hashedFiles = []string{"rules.json", "keys.json", "algorithms.json"}

type wordMacro struct {
	Join     string     `json:"join"`
	Words    [][]string `json:"words"`
	FromKeys string     `json:"fromKeys"`
}

type rulesFile struct {
	SpecVersion int                        `json:"specVersion"`
	Macros      map[string]json.RawMessage `json:"macros"`
	Patterns    struct {
		Placeholder string `json:"placeholder"`
	} `json:"patterns"`
	Pipeline []json.RawMessage `json:"pipeline"`
	Full     []json.RawMessage `json:"full"`
}

type keysFile struct {
	SpecVersion        int        `json:"specVersion"`
	StructuralSkipKeys []string   `json:"structuralSkipKeys"`
	SecretWords        [][]string `json:"secretWords"`
	ExtraSequences     [][]string `json:"extraSequences"`
	ExactKeys          []string   `json:"exactKeys"`
	JoinedExtra        []string   `json:"joinedExtra"`
	SuffixWords        []string   `json:"suffixWords"`
	PrefixWords        []string   `json:"prefixWords"`
	PassLastWord       string     `json:"passLastWord"`
	CountWords         []string   `json:"countWords"`
}

type algorithmsFile struct {
	SpecVersion int `json:"specVersion"`
	RuleIDs     struct {
		KeyContext string `json:"keyContext"`
		SizeLimit  string `json:"sizeLimit"`
		DepthLimit string `json:"depthLimit"`
		Circular   string `json:"circular"`
		Failed     string `json:"failed"`
		Error      string `json:"error"`
	} `json:"ruleIds"`
	Text struct {
		MinScanLength int `json:"minScanLength"`
	} `json:"text"`
	Placeholder struct {
		Open          string   `json:"open"`
		Close         string   `json:"close"`
		StripPrefixes []string `json:"stripPrefixes"`
	} `json:"placeholder"`
	Evidence struct {
		QuoteChars       string   `json:"quoteChars"`
		Classes          []string `json:"classes"`
		MinClasses       int      `json:"minClasses"`
		EntropyThreshold float64  `json:"entropyThreshold"`
	} `json:"evidence"`
	Trivial struct {
		Words        []string   `json:"words"`
		MaskChars    []string   `json:"maskChars"`
		Wrappers     [][]string `json:"wrappers"`
		WrapperInner string     `json:"wrapperInner"`
	} `json:"trivial"`
	DocPlaceholder struct {
		Prefixes  []string `json:"prefixes"`
		Suffixes  []string `json:"suffixes"`
		Separator string   `json:"separator"`
	} `json:"docPlaceholder"`
	Sync struct {
		MaxChars    int `json:"maxChars"`
		MaxDepth    int `json:"maxDepth"`
		MaxNodes    int `json:"maxNodes"`
		MaxKeyChars int `json:"maxKeyChars"`
	} `json:"sync"`
	Full struct {
		ScanWindow  int `json:"scanWindow"`
		ScanOverlap int `json:"scanOverlap"`
		ScanCap     int `json:"scanCap"`
	} `json:"full"`
	Strict struct {
		MaxChars int `json:"maxChars"`
		MaxDepth int `json:"maxDepth"`
		MaxNodes int `json:"maxNodes"`
	} `json:"strict"`
	Letters struct {
		UnicodeVersion string `json:"unicodeVersion"`
		Ranges         string `json:"ranges"`
	} `json:"letters"`
}

type specFileSet struct {
	rules      []byte
	keys       []byte
	algorithms []byte
}

var errSpecRejected = errors.New("redaction: embedded spec rejected")
var errSpecIntegrity = errors.New("redaction: embedded spec failed the integrity check")

func readEmbedded() (specFileSet, error) {
	var files specFileSet
	var err error
	if files.rules, err = specFiles.ReadFile("spec/rules.json"); err != nil {
		return files, errSpecRejected
	}
	if files.keys, err = specFiles.ReadFile("spec/keys.json"); err != nil {
		return files, errSpecRejected
	}
	if files.algorithms, err = specFiles.ReadFile("spec/algorithms.json"); err != nil {
		return files, errSpecRejected
	}
	return files, nil
}

// specDigest is SHA-256 of `name NUL bytes NUL` for the three files in order, as lower-case hex.
func specDigest(files specFileSet) string {
	sum := sha256.New()
	contents := [][]byte{files.rules, files.keys, files.algorithms}
	for i, name := range hashedFiles {
		sum.Write([]byte(name))
		sum.Write([]byte{0})
		sum.Write(contents[i])
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// verifySpec checks the files against the generated hash constant.
func verifySpec(files specFileSet, want string) error {
	if specDigest(files) != want {
		return errSpecIntegrity
	}
	return nil
}

// loadedSpec is the parsed spec with every pattern expanded.
type loadedSpec struct {
	rules      rulesFile
	keys       keysFile
	algorithms algorithmsFile
	macros     map[string]string
}

// hasValidScanWindows: the windows overlap by less than their size (so the scan moves forward) and
// the cap holds at least one window.
func hasValidScanWindows(window int, overlap int, scanCap int) bool {
	movesForward := overlap >= 0 && overlap < window
	return movesForward && scanCap >= window
}

func decodeSpec(files specFileSet) (*loadedSpec, error) {
	spec := &loadedSpec{}
	if err := json.Unmarshal(files.rules, &spec.rules); err != nil {
		return nil, errSpecRejected
	}
	if err := json.Unmarshal(files.keys, &spec.keys); err != nil {
		return nil, errSpecRejected
	}
	if err := json.Unmarshal(files.algorithms, &spec.algorithms); err != nil {
		return nil, errSpecRejected
	}
	versions := []int{spec.rules.SpecVersion, spec.keys.SpecVersion, spec.algorithms.SpecVersion}
	for _, version := range versions {
		if version != supportedSpecVersion {
			return nil, errSpecRejected
		}
	}
	hasRules := len(spec.rules.Pipeline) > 0 && len(spec.rules.Full) > 0
	if !hasRules || len(spec.keys.SecretWords) == 0 || spec.algorithms.Letters.Ranges == "" {
		return nil, errSpecRejected
	}
	if !hasValidScanWindows(spec.algorithms.Full.ScanWindow, spec.algorithms.Full.ScanOverlap,
		spec.algorithms.Full.ScanCap) {
		return nil, errSpecRejected
	}
	macros, err := spec.expandMacros()
	if err != nil {
		return nil, err
	}
	spec.macros = macros
	return spec, nil
}

// asciiTwoCase writes a lower-case ASCII letter as a two-case class (`a` as `[aA]`).
func asciiTwoCase(word string) string {
	var out strings.Builder
	for _, char := range word {
		if char >= 'a' && char <= 'z' {
			out.WriteString("[" + string(char) + strings.ToUpper(string(char)) + "]")
			continue
		}
		out.WriteRune(char)
	}
	return out.String()
}

func (s *loadedSpec) expandWordMacro(macro wordMacro) string {
	sequences := macro.Words
	if macro.FromKeys == "secretWords" {
		sequences = s.keys.SecretWords
	}
	alternatives := make([]string, 0, len(sequences))
	for _, parts := range sequences {
		cased := make([]string, len(parts))
		for i, part := range parts {
			cased[i] = asciiTwoCase(part)
		}
		alternatives = append(alternatives, strings.Join(cased, macro.Join))
	}
	return "(?:" + strings.Join(alternatives, "|") + ")"
}

// expandMacros turns every macro into pattern text (word macros into an alternation).
func (s *loadedSpec) expandMacros() (map[string]string, error) {
	macros := make(map[string]string, len(s.rules.Macros))
	for name, raw := range s.rules.Macros {
		var plain string
		if json.Unmarshal(raw, &plain) == nil {
			macros[name] = plain
			continue
		}
		var word wordMacro
		if json.Unmarshal(raw, &word) != nil {
			return nil, errSpecRejected
		}
		if word.FromKeys != "" && word.FromKeys != "secretWords" {
			return nil, errSpecRejected
		}
		macros[name] = s.expandWordMacro(word)
	}
	return macros, nil
}

var macroReference = regexp.MustCompile(`\{\{([A-Z_]+)\}\}`)

// expand replaces every {{NAME}} by its macro, repeatedly, until nothing changes.
func (s *loadedSpec) expand(template string) (string, error) {
	current := template
	for depth := 0; depth <= maxMacroDepth; depth++ {
		var failed bool
		next := macroReference.ReplaceAllStringFunc(current, func(reference string) string {
			body, ok := s.macros[reference[2:len(reference)-2]]
			failed = failed || !ok
			return body
		})
		if failed {
			return "", errSpecRejected
		}
		if next == current {
			return next, nil
		}
		current = next
	}
	return "", errSpecRejected
}
