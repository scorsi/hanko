package run

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/issuer"
)

// A final ACME failure, issuer.ErrNoQuickRetry, as Issue would wrap it.
type finalACME struct{}

func (finalACME) Error() string        { return "acme validation failed (HTTP 400, problem dns)" }
func (finalACME) Is(target error) bool { return target == issuer.ErrNoQuickRetry }

func TestNoQuickRetry(t *testing.T) {
	for _, c := range []struct {
		err   error
		final bool
	}{
		{fmt.Errorf("hanko-ca x: %w", grpcstatus.Error(codes.PermissionDenied, "")), true},
		{fmt.Errorf("hanko-ca x: %w", grpcstatus.Error(codes.InvalidArgument, "")), true},
		{fmt.Errorf("hanko-ca x: %w", grpcstatus.Error(codes.FailedPrecondition, "")), true},
		{fmt.Errorf("hanko-ca x: %w", grpcstatus.Error(codes.Unavailable, "")), false},
		{fmt.Errorf("hanko-ca x: %w", grpcstatus.Error(codes.DeadlineExceeded, "")), false},
		{fmt.Errorf("x: %w", finalACME{}), true},
		{context.DeadlineExceeded, false},
		{errors.New("dns update refused"), false},
	} {
		if got := noQuickRetry(c.err); got != c.final {
			t.Errorf("%v: final %v, want %v", c.err, got, c.final)
		}
	}
}

// TestRunNoQuickRetryWins: one final failure makes the whole run final, even beside a transient
// one; transient failures alone are not.
func TestRunNoQuickRetryWins(t *testing.T) {
	r, iss, _ := setup(t)
	cv := config.Certificate{Name: "cv", Hosts: []string{"cv.example.org"}, Group: home.Group}
	iss.fail = "uchi.example.org"
	if err := r.Run(context.Background(), []config.Certificate{home}); err == nil || errors.Is(err, issuer.ErrNoQuickRetry) {
		t.Fatalf("transient: %v", err)
	}
	iss.err = finalACME{}
	if err := r.Run(context.Background(), []config.Certificate{home}); !errors.Is(err, issuer.ErrNoQuickRetry) {
		t.Fatalf("final: %v", err)
	}
	r.Internal = unreachable{}
	cv.Issuer = "internal"
	cv.SpiffeID = "spiffe://uchi.example.org/vm/cv"
	if err := r.Run(context.Background(), []config.Certificate{cv, home}); !errors.Is(err, issuer.ErrNoQuickRetry) {
		t.Fatalf("mixed: %v", err)
	}
}

type unreachable struct{}

func (unreachable) Sign(context.Context, string) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, grpcstatus.Error(codes.Unavailable, "")
}
func (unreachable) Bundle(context.Context) ([]byte, error) {
	return nil, grpcstatus.Error(codes.Unavailable, "")
}
