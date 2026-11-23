package redaction

// theEngine is the interpreter of the embedded spec. The package refuses to start (and so
// processes no input) when the embedded files do not match the generated hash, hold another spec
// version or no rules. The panic message names the failure, never the data.
var theEngine *engine

func init() {
	files, err := readEmbedded()
	if err != nil {
		panic(err)
	}
	if err := verifySpec(files, specHash); err != nil {
		panic(err)
	}
	spec, err := decodeSpec(files)
	if err != nil {
		panic(err)
	}
	theEngine, err = newEngine(spec)
	if err != nil {
		panic(err)
	}
	redactedOpen = theEngine.placeholders.marker
}
