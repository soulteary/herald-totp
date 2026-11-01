package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	rediskit "github.com/soulteary/redis-kit/client"
)

// These tests use the production redis-kit client against a disposable real
// Redis instance. Their keys are unique; they never flush a shared database.
func realRedisCompatibilityStore(t *testing.T) (*Store, context.Context, string) {
	t.Helper()
	addr := os.Getenv("HERALD_TOTP_REDIS_TEST_ADDR")
	if addr == "" {
		if os.Getenv("HERALD_TOTP_REDIS_TEST_REQUIRED") == "1" {
			t.Fatal("HERALD_TOTP_REDIS_TEST_ADDR is required")
		}
		t.Skip("set HERALD_TOTP_REDIS_TEST_ADDR to a disposable Redis instance")
	}
	rdb, err := rediskit.NewClient(rediskit.DefaultConfig().WithAddr(addr).WithDB(15))
	requireRedisCompatibilityNoError(t, err)
	t.Cleanup(func() { _ = rdb.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	subject := fmt.Sprintf("compat-%s-%d", t.Name(), time.Now().UnixNano())
	st := NewStore(rdb, time.Second, 0, time.Minute, time.Second, time.Second)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = st.DeleteSubject(cleanup, subject)
		_ = rdb.Del(cleanup, chUsedPrefix+subject, chUsedPrefix+subject+"-second", rateSubjectPrefix+subject).Err()
	})
	return st, ctx, subject
}

func requireRedisCompatibilityNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRedisCompatibilityEnrollmentAndReplay(t *testing.T) {
	st, ctx, subject := realRedisCompatibilityStore(t)
	enrollment := &Enrollment{EnrollID: subject, Subject: subject, SecretEnc: "encrypted-test-secret"}
	requireRedisCompatibilityNoError(t, st.SaveEnrollment(ctx, enrollment))
	duplicate := *enrollment
	duplicate.EnrollID += "-duplicate"
	if err := st.SaveEnrollment(ctx, &duplicate); !errors.Is(err, ErrEnrollmentInProgress) {
		t.Fatalf("duplicate enrollment: %v", err)
	}
	credential := &Credential{Subject: subject, SecretEnc: enrollment.SecretEnc, LastUsedStep: 1}
	confirmed, err := st.ConfirmEnrollment(ctx, enrollment, credential, []BackupCodeEntry{{CodeHash: "backup-test-hash"}})
	requireRedisCompatibilityNoError(t, err)
	if !confirmed {
		t.Fatal("enrollment was not confirmed")
	}
	confirmed, err = st.ConfirmEnrollment(ctx, enrollment, credential, nil)
	requireRedisCompatibilityNoError(t, err)
	if confirmed {
		t.Fatal("consumed enrollment was confirmed twice")
	}
	claimed, err := st.ClaimCredentialStepAndChallenge(ctx, subject, 10, 10, subject)
	requireRedisCompatibilityNoError(t, err)
	if !claimed {
		t.Fatal("new step and challenge were not claimed")
	}
	claimed, err = st.ClaimCredentialStepAndChallenge(ctx, subject, 11, 11, subject)
	requireRedisCompatibilityNoError(t, err)
	if claimed {
		t.Fatal("challenge replay advanced the credential")
	}
	got, err := st.GetCredential(ctx, subject)
	requireRedisCompatibilityNoError(t, err)
	if got == nil || got.LastUsedStep != 10 {
		t.Fatalf("replay changed credential: %+v", got)
	}
}

func TestRedisCompatibilityConcurrentBackupConsumption(t *testing.T) {
	st, ctx, subject := realRedisCompatibilityStore(t)
	requireRedisCompatibilityNoError(t, st.SaveBackupCodes(ctx, subject, []BackupCodeEntry{{CodeHash: "first"}, {CodeHash: "second"}}))
	var successes atomic.Int32
	failures := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			consumed, err := st.ConsumeBackupCodeAndClaimChallenge(ctx, subject, "first", subject)
			if err != nil {
				failures <- err
			}
			if consumed {
				successes.Add(1)
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("consume: %v", err)
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("consumed %d times, want one", got)
	}
	consumed, err := st.ConsumeBackupCodeAndClaimChallenge(ctx, subject, "second", subject)
	requireRedisCompatibilityNoError(t, err)
	if consumed {
		t.Fatal("replayed challenge consumed another backup code")
	}
	consumed, err = st.ConsumeBackupCodeAndClaimChallenge(ctx, subject, "second", subject+"-second")
	requireRedisCompatibilityNoError(t, err)
	if !consumed {
		t.Fatal("failed replay discarded an unused backup code")
	}
}

func TestRedisCompatibilityLuaExpiry(t *testing.T) {
	st, ctx, subject := realRedisCompatibilityStore(t)
	enrollment := &Enrollment{EnrollID: subject, Subject: subject, SecretEnc: "encrypted-test-secret"}
	requireRedisCompatibilityNoError(t, st.SaveEnrollment(ctx, enrollment))
	for want := int64(1); want <= 2; want++ {
		got, err := st.IncrRateSubject(ctx, subject)
		requireRedisCompatibilityNoError(t, err)
		if got != want {
			t.Fatalf("rate=%d, want %d", got, want)
		}
	}
	ttl, err := st.rdb.PTTL(ctx, rateSubjectPrefix+subject).Result()
	requireRedisCompatibilityNoError(t, err)
	if ttl <= 0 || ttl > time.Second {
		t.Fatalf("rate window has invalid TTL %v", ttl)
	}
	waitForRedisCompatibilityExpiry(t, ctx, st.rdb, enrollPrefix+subject, enrollSubjectPrefix+subject, rateSubjectPrefix+subject)
	got, err := st.IncrRateSubject(ctx, subject)
	requireRedisCompatibilityNoError(t, err)
	if got != 1 {
		t.Fatalf("expired rate window resumed at %d", got)
	}
}

func waitForRedisCompatibilityExpiry(t *testing.T, ctx context.Context, rdb *redis.Client, keys ...string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining, err := rdb.Exists(ctx, keys...).Result()
		requireRedisCompatibilityNoError(t, err)
		if remaining == 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("Lua-created enrollment/rate keys did not expire")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

// The transaction reaches Redis, but its acknowledgement is lost to the caller.
// A retry must observe the committed counter/challenge instead of accepting twice.
type lostCommitReplyHook struct{ fired atomic.Bool }

func (h *lostCommitReplyHook) DialHook(next redis.DialHook) redis.DialHook          { return next }
func (h *lostCommitReplyHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return next }
func (h *lostCommitReplyHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, commands []redis.Cmder) error {
		err := next(ctx, commands)
		if err == nil && len(commands) > 0 && commands[0].Name() == "multi" && h.fired.CompareAndSwap(false, true) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
}

func TestRedisCompatibilityLostCommitReply(t *testing.T) {
	st, ctx, subject := realRedisCompatibilityStore(t)
	requireRedisCompatibilityNoError(t, st.SaveCredential(ctx, &Credential{Subject: subject, Enabled: true, LastUsedStep: 1}))
	hook := &lostCommitReplyHook{}
	st.rdb.AddHook(hook)
	claimed, err := st.ClaimCredentialStepAndChallenge(ctx, subject, 10, 10, subject)
	if claimed || !errors.Is(err, io.ErrUnexpectedEOF) || !hook.fired.Load() {
		t.Fatalf("lost reply = (%v,%v), injected=%v", claimed, err, hook.fired.Load())
	}
	current, err := st.GetCredential(ctx, subject)
	requireRedisCompatibilityNoError(t, err)
	if current == nil || current.LastUsedStep != 10 {
		t.Fatalf("commit was not persisted: %+v", current)
	}
	used, err := st.IsChallengeUsed(ctx, subject)
	requireRedisCompatibilityNoError(t, err)
	if !used {
		t.Fatal("committed challenge was not retained")
	}
	claimed, err = st.ClaimCredentialStepAndChallenge(ctx, subject, 10, 11, subject)
	requireRedisCompatibilityNoError(t, err)
	if claimed {
		t.Fatal("retry accepted the same verification after lost acknowledgement")
	}
}
