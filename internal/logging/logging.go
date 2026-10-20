// Package logging writes nisshi log schema v1 lines with log/slog (ADR 0007): the reference
// ReplaceAttr of nisshi's log-schema, `event` as an attribute, `msg` dropped when empty. Copied
// from genkan's internal/logging, not shared (nisshi ADR 0004).
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// TS is the schema's `ts` format: UTC, exactly 9 fractional digits.
const TS = "2006-01-02T15:04:05.000000000Z"

// New returns a JSON logger on w whose lines pass `nisshi validate --logs` as long as every call
// carries an "event" attribute and "err" only at warn or error.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) > 0 {
				return a
			}
			switch a.Key {
			case slog.TimeKey:
				return slog.String("ts", a.Value.Time().UTC().Format(TS))
			case slog.LevelKey:
				return slog.String("level", strings.ToLower(a.Value.String()))
			case slog.MessageKey:
				if a.Value.String() == "" {
					return slog.Attr{} // msg is optional in the schema
				}
			}
			return a
		},
	})
	return slog.New(h).With("v", 1)
}
