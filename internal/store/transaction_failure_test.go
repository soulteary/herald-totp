package store

import (
	"context"
	"errors"
	"github.com/alicebob/miniredis/v2/server"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

type transactionFailureHook struct{ err error }

func (h transactionFailureHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h transactionFailureHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h transactionFailureHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "watch" {
			return h.err
		}
		return next(ctx, cmd)
	}
}

func TestTransactionContentionExhaustionFailsClosed(t *testing.T) {
	for _, operation := range []string{"credential", "enrollment", "backup"} {
		t.Run(operation, func(t *testing.T) {
			st, mr := newTestStore(t)
			defer mr.Close()
			st.rdb.AddHook(transactionFailureHook{err: redis.TxFailedErr})
			var ok bool
			var err error
			switch operation {
			case "credential":
				ok, err = st.ClaimCredentialStep(context.Background(), "user", 1, 1)
			case "enrollment":
				ok, err = st.ConfirmEnrollment(context.Background(), &Enrollment{EnrollID: "enroll"}, &Credential{Subject: "user"}, nil)
			case "backup":
				ok, err = st.ConsumeBackupCode(context.Background(), "user", "hash")
			}
			if ok || !errors.Is(err, redis.TxFailedErr) {
				t.Fatalf("transaction=(%v,%v), want failed contention", ok, err)
			}
			if len(mr.Keys()) != 0 {
				t.Fatal("failed transaction wrote state")
			}
		})
	}
}

func TestTransactionReadFailuresPreserveState(t *testing.T) {
	for _, tt := range []struct{ name, command, key string }{
		{"credential challenge", "EXISTS", chUsedPrefix + "challenge"},
		{"enrollment index", "GET", enrollSubjectPrefix + "user"},
		{"enrollment credential", "EXISTS", credPrefix + "user"},
		{"backup read", "GET", backupPrefix + "user"},
		{"backup challenge", "EXISTS", chUsedPrefix + "challenge"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, mr := newTestStore(t)
			defer mr.Close()
			ctx := context.Background()
			enrollment := &Enrollment{EnrollID: "enroll", Subject: "user", SecretEnc: "encrypted"}
			if err := st.SaveEnrollment(ctx, enrollment); err != nil {
				t.Fatal(err)
			}
			if err := st.SaveCredential(ctx, &Credential{Subject: "user", LastUsedStep: 1}); err != nil {
				t.Fatal(err)
			}
			if err := st.SaveBackupCodes(ctx, "user", []BackupCodeEntry{{CodeHash: "hash"}}); err != nil {
				t.Fatal(err)
			}
			before := mr.Dump()
			mr.Server().SetPreHook(func(peer *server.Peer, command string, args ...string) bool {
				if strings.EqualFold(command, tt.command) && len(args) > 0 && args[0] == tt.key {
					peer.WriteError("ERR injected read failure")
					return true
				}
				return false
			})
			var ok bool
			var err error
			switch {
			case strings.HasPrefix(tt.name, "credential"):
				ok, err = st.ClaimCredentialStepAndChallenge(ctx, "user", 2, 2, "challenge")
			case strings.HasPrefix(tt.name, "enrollment"):
				ok, err = st.ConfirmEnrollment(ctx, enrollment, &Credential{Subject: "user"}, nil)
			default:
				ok, err = st.ConsumeBackupCodeAndClaimChallenge(ctx, "user", "hash", "challenge")
			}
			if ok || err == nil {
				t.Fatalf("read failure=(%v,%v)", ok, err)
			}
			if after := mr.Dump(); after != before {
				t.Fatal("read failure changed stored state")
			}
		})
	}
}
