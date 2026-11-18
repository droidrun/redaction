package redaction

import (
	"strings"
	"testing"
)

const benchLine = `{"level":"info","ts":"2026-11-18T09:12:44.512Z","service":"devices-api","msg":"device ` +
	`allocated","device_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","org":"acme","region":"eu-west-1",` +
	`"latency_ms":42,"path":"/v1/devices/3fa85f64/connect?page=2&sort=asc","user_agent":"Mozilla/5.0 ` +
	`(X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36","note":"` +
	`retrying after transient failure in the upstream provider, attempt 2 of 5"}` + "\n"

func repeatToSize(unit string, size int) string {
	return strings.Repeat(unit, size/len(unit)+1)[:size]
}

func BenchmarkRedactTextLogLine(b *testing.B) {
	line := repeatToSize(benchLine, 2048)
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		RedactText(line, Options{})
	}
}

func BenchmarkRedactTextLogLineWithSecret(b *testing.B) {
	line := repeatToSize(benchLine, 2000) + " password=Zq9abcDEF123ghi_x"
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		RedactText(line, Options{})
	}
}

func BenchmarkRedactText4MB(b *testing.B) {
	text := repeatToSize(benchLine, 3_900_000)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		RedactText(text, Options{})
	}
}
