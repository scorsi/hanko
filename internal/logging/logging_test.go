package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ts = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$`)

func TestSchemaLine(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelInfo)
	log.Info("", "event", "certificate-valid", "certificate", "home")
	log.Error("", "event", "reload-failed", "unit", "consumer.service", "err", "boom")
	log.Debug("", "event", "hidden")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", lines)
	}
	want := []map[string]any{
		{"v": 1.0, "level": "info", "event": "certificate-valid", "certificate": "home"},
		{"v": 1.0, "level": "error", "event": "reload-failed", "unit": "consumer.service", "err": "boom"},
	}
	for i, line := range lines {
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		s, _ := got["ts"].(string)
		if !ts.MatchString(s) {
			t.Errorf("line %d: ts %q is not UTC with 9 fractional digits", i, s)
		}
		delete(got, "ts")
		if len(got) != len(want[i]) {
			t.Errorf("line %d: got %v, want %v", i, got, want[i])
		}
		for k, v := range want[i] {
			if got[k] != v {
				t.Errorf("line %d: %s = %v, want %v", i, k, got[k], v)
			}
		}
	}
	if strings.Contains(buf.String(), `"msg"`) {
		t.Errorf("empty msg kept: %s", buf.String())
	}
}

// slog's default RFC3339Nano drops trailing zeros; the schema needs exactly 9 digits.
func TestTrailingZeros(t *testing.T) {
	var buf bytes.Buffer
	h := New(&buf, slog.LevelInfo).Handler()
	at, _ := time.Parse(time.RFC3339Nano, "2026-10-19T10:14:03.5+02:00") // local time, 1 digit
	r := slog.NewRecord(at, slog.LevelError, "", 0)
	r.AddAttrs(slog.String("event", "x"), slog.String("err", "e"))
	h.Handle(t.Context(), r)
	if !strings.HasPrefix(buf.String(), `{"ts":"2026-10-19T08:14:03.500000000Z","level":"error","v":1,"event":"x"`) {
		t.Errorf("got %s", buf.String())
	}
}
