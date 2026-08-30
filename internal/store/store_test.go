package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	enrollTTL := 10 * time.Minute
	chUsedTTL := 5 * time.Minute
	rateSubTTL := time.Hour
	rateIPTTL := time.Minute
	st := NewStore(rdb, enrollTTL, 0, chUsedTTL, rateSubTTL, rateIPTTL)
	return st, mr
}

func TestSaveGetCredential(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	cred := &Credential{
		Subject: "user1", SecretEnc: "enc1", Issuer: "Herald", Label: "user1",
		Period: 30, Digits: 6, Algo: "SHA1", Enabled: true,
		LastUsedStep: 0, CreatedAt: 1, UpdatedAt: 1,
	}
	if err := st.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	got, err := st.GetCredential(ctx, "user1")
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got == nil || got.Subject != "user1" || got.SecretEnc != "enc1" || !got.Enabled {
		t.Errorf("GetCredential = %+v, want Subject=user1 Enabled=true", got)
	}
	got, _ = st.GetCredential(ctx, "nonexistent")
	if got != nil {
		t.Errorf("GetCredential(nonexistent) = %v, want nil", got)
	}
}

func TestClaimCredentialStep(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	cred := &Credential{
		Subject: "claim-user", SecretEnc: "enc", Period: 30, Digits: 6,
		Enabled: true, LastUsedStep: 100, CreatedAt: 1, UpdatedAt: 1,
	}
	if err := st.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	claimed, err := st.ClaimCredentialStep(ctx, cred.Subject, 101, 2)
	if err != nil || !claimed {
		t.Fatalf("ClaimCredentialStep = (%v, %v), want true", claimed, err)
	}
	claimed, err = st.ClaimCredentialStep(ctx, cred.Subject, 101, 3)
	if err != nil || claimed {
		t.Fatalf("repeated ClaimCredentialStep = (%v, %v), want false", claimed, err)
	}
	stored, err := st.GetCredential(ctx, cred.Subject)
	if err != nil || stored.LastUsedStep != 101 || stored.UpdatedAt != 2 {
		t.Fatalf("stored credential = (%+v, %v)", stored, err)
	}
	if claimed, err := st.ClaimCredentialStep(ctx, "missing", 1, 1); err != redis.Nil || claimed {
		t.Fatalf("missing credential claim = (%v, %v), want redis.Nil", claimed, err)
	}
}

func TestClaimCredentialStep_Concurrent(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	cred := &Credential{Subject: "concurrent-user", SecretEnc: "enc", Period: 30, Digits: 6, Enabled: true}
	if err := st.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	const workers = 16
	start := make(chan struct{})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claimed, err := st.ClaimCredentialStep(ctx, cred.Subject, 500, 10)
			if err != nil {
				t.Errorf("ClaimCredentialStep: %v", err)
				return
			}
			if claimed {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful claims = %d, want 1", got)
	}
}

func TestSaveGetEnrollment(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	e := &Enrollment{
		EnrollID: "e_abc", Subject: "user1", SecretEnc: "enc1", Issuer: "Herald",
		Label: "user1", Period: 30, Digits: 6, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), CreatedAt: time.Now().Unix(),
	}
	if err := st.SaveEnrollment(ctx, e); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}
	got, err := st.GetEnrollment(ctx, "e_abc")
	if err != nil {
		t.Fatalf("GetEnrollment: %v", err)
	}
	if got == nil || got.EnrollID != "e_abc" || got.Subject != "user1" {
		t.Errorf("GetEnrollment = %+v", got)
	}
	got, _ = st.GetEnrollment(ctx, "e_none")
	if got != nil {
		t.Errorf("GetEnrollment(none) = %v, want nil", got)
	}
	if err := st.DeleteEnrollment(ctx, "e_abc"); err != nil {
		t.Fatalf("DeleteEnrollment: %v", err)
	}
	got, _ = st.GetEnrollment(ctx, "e_abc")
	if got != nil {
		t.Errorf("GetEnrollment after Delete = %v, want nil", got)
	}
	if err := st.SaveEnrollment(ctx, &Enrollment{
		EnrollID: "e_replacement", Subject: e.Subject, SecretEnc: "enc2",
	}); err != nil {
		t.Fatalf("new enrollment after DeleteEnrollment: %v", err)
	}
}

func TestSaveEnrollment_RejectsCredentialAndConcurrentEnrollment(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	first := &Enrollment{EnrollID: "e_first", Subject: "same-user", SecretEnc: "enc1"}
	if err := st.SaveEnrollment(ctx, first); err != nil {
		t.Fatalf("SaveEnrollment(first): %v", err)
	}
	second := &Enrollment{EnrollID: "e_second", Subject: "same-user", SecretEnc: "enc2"}
	if err := st.SaveEnrollment(ctx, second); !errors.Is(err, ErrEnrollmentInProgress) {
		t.Fatalf("SaveEnrollment(second) error = %v, want ErrEnrollmentInProgress", err)
	}

	credential := &Credential{Subject: "enrolled-user", SecretEnc: "existing", Enabled: true}
	if err := st.SaveCredential(ctx, credential); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if err := st.SaveEnrollment(ctx, &Enrollment{EnrollID: "e_existing", Subject: credential.Subject}); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("SaveEnrollment(existing) error = %v, want ErrCredentialExists", err)
	}
}

func TestConfirmEnrollment_DoesNotOverwriteCredential(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	enrollment := &Enrollment{EnrollID: "e_no_overwrite", Subject: "protected-user", SecretEnc: "new-secret"}
	if err := st.SaveEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}
	existing := &Credential{Subject: enrollment.Subject, SecretEnc: "existing-secret", Enabled: true}
	if err := st.SaveCredential(ctx, existing); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	confirmed, err := st.ConfirmEnrollment(ctx, enrollment, &Credential{
		Subject: enrollment.Subject, SecretEnc: enrollment.SecretEnc, Enabled: true,
	}, nil)
	if confirmed || !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("ConfirmEnrollment = (%v, %v), want false, ErrCredentialExists", confirmed, err)
	}
	got, err := st.GetCredential(ctx, enrollment.Subject)
	if err != nil || got == nil || got.SecretEnc != existing.SecretEnc {
		t.Fatalf("credential after conflict = (%+v, %v)", got, err)
	}
	if pending, err := st.GetEnrollment(ctx, enrollment.EnrollID); err != nil || pending != nil {
		t.Fatalf("conflicting enrollment was not consumed: (%+v, %v)", pending, err)
	}
}

func TestDeleteSubject_InvalidatesPendingEnrollment(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	enrollment := &Enrollment{EnrollID: "e_revoke_pending", Subject: "revoke-pending", SecretEnc: "secret"}
	if err := st.SaveEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}
	if err := st.DeleteSubject(ctx, enrollment.Subject); err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}
	if got, err := st.GetEnrollment(ctx, enrollment.EnrollID); err != nil || got != nil {
		t.Fatalf("pending enrollment after DeleteSubject = (%+v, %v)", got, err)
	}
	if err := st.SaveEnrollment(ctx, &Enrollment{EnrollID: "e_after_revoke", Subject: enrollment.Subject}); err != nil {
		t.Fatalf("new enrollment after DeleteSubject: %v", err)
	}
}

func TestConfirmEnrollment(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	enrollment := &Enrollment{EnrollID: "e_confirm", Subject: "confirm-user", SecretEnc: "secret", Period: 30, Digits: 6}
	credential := &Credential{Subject: enrollment.Subject, SecretEnc: enrollment.SecretEnc, Period: 30, Digits: 6, Enabled: true}
	entries := []BackupCodeEntry{{CodeHash: "hash1"}, {CodeHash: "hash2"}}
	if err := st.SaveEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	confirmed, err := st.ConfirmEnrollment(ctx, enrollment, credential, entries)
	if err != nil || !confirmed {
		t.Fatalf("ConfirmEnrollment = (%v, %v), want true", confirmed, err)
	}
	if got, err := st.GetEnrollment(ctx, enrollment.EnrollID); err != nil || got != nil {
		t.Fatalf("enrollment after confirm = (%+v, %v), want nil", got, err)
	}
	if got, err := st.GetCredential(ctx, credential.Subject); err != nil || got == nil || !got.Enabled {
		t.Fatalf("credential after confirm = (%+v, %v)", got, err)
	}
	if got, err := st.GetBackupCodes(ctx, credential.Subject); err != nil || len(got) != len(entries) {
		t.Fatalf("backup codes after confirm = (%+v, %v)", got, err)
	}
	confirmed, err = st.ConfirmEnrollment(ctx, enrollment, credential, entries)
	if err != nil || confirmed {
		t.Fatalf("second ConfirmEnrollment = (%v, %v), want false", confirmed, err)
	}
}

func TestConfirmEnrollment_PreIndexRecordFailsClosed(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	enrollment := &Enrollment{
		EnrollID: "e_pre_index", Subject: "upgrade-user", SecretEnc: "legacy-secret",
		Period: 30, Digits: 6, CreatedAt: time.Now().Unix(),
	}
	data, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatalf("marshal enrollment: %v", err)
	}
	// Simulate a record written by a version that predates subject indexes.
	if err := st.rdb.Set(ctx, enrollPrefix+enrollment.EnrollID, data, st.enrollTTL).Err(); err != nil {
		t.Fatalf("seed pre-index enrollment: %v", err)
	}

	confirmed, err := st.ConfirmEnrollment(ctx, enrollment, &Credential{
		Subject: enrollment.Subject, SecretEnc: enrollment.SecretEnc,
	}, nil)
	if err != nil || confirmed {
		t.Fatalf("ConfirmEnrollment(pre-index) = (%v, %v), want false, nil", confirmed, err)
	}
	if got, err := st.GetCredential(ctx, enrollment.Subject); err != nil || got != nil {
		t.Fatalf("credential after pre-index confirmation = (%+v, %v), want nil, nil", got, err)
	}
	if got, err := st.GetEnrollment(ctx, enrollment.EnrollID); err != nil || got == nil {
		t.Fatalf("pre-index enrollment should remain available for migration handling: (%+v, %v)", got, err)
	}
}

func TestConfirmEnrollment_Concurrent(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	enrollment := &Enrollment{EnrollID: "e_concurrent", Subject: "confirm-concurrent", SecretEnc: "secret", Period: 30, Digits: 6}
	credential := &Credential{Subject: enrollment.Subject, SecretEnc: enrollment.SecretEnc, Period: 30, Digits: 6, Enabled: true}
	entries := []BackupCodeEntry{{CodeHash: "hash"}}
	if err := st.SaveEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	const workers = 16
	start := make(chan struct{})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			confirmed, err := st.ConfirmEnrollment(ctx, enrollment, credential, entries)
			if err != nil {
				t.Errorf("ConfirmEnrollment: %v", err)
				return
			}
			if confirmed {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful confirmations = %d, want 1", got)
	}
}

func TestClaimCredentialStepAndChallenge_ConcurrentDifferentSteps(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	const subject = "atomic-totp"
	const challengeID = "shared-totp-challenge"
	if err := st.SaveCredential(ctx, &Credential{Subject: subject, Enabled: true}); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	const workers = 16
	start := make(chan struct{})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 1; i <= workers; i++ {
		step := int64(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claimed, err := st.ClaimCredentialStepAndChallenge(ctx, subject, step, step, challengeID)
			if err != nil {
				t.Errorf("ClaimCredentialStepAndChallenge: %v", err)
				return
			}
			if claimed {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful atomic TOTP claims = %d, want 1", got)
	}
	if used, err := st.IsChallengeUsed(ctx, challengeID); err != nil || !used {
		t.Fatalf("challenge used = (%v, %v), want true", used, err)
	}
}

func TestConsumeBackupCodeAndClaimChallenge_ConcurrentDifferentCodes(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	const subject = "atomic-backup"
	const challengeID = "shared-backup-challenge"
	const workers = 16
	entries := make([]BackupCodeEntry, workers)
	for i := range entries {
		entries[i].CodeHash = fmt.Sprintf("hash-%d", i)
	}
	if err := st.SaveBackupCodes(ctx, subject, entries); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}

	start := make(chan struct{})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range workers {
		hash := entries[i].CodeHash
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			consumed, err := st.ConsumeBackupCodeAndClaimChallenge(ctx, subject, hash, challengeID)
			if err != nil {
				t.Errorf("ConsumeBackupCodeAndClaimChallenge: %v", err)
				return
			}
			if consumed {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful atomic backup claims = %d, want 1", got)
	}
	got, err := st.GetBackupCodes(ctx, subject)
	if err != nil {
		t.Fatalf("GetBackupCodes: %v", err)
	}
	usedCodes := 0
	for _, entry := range got {
		if entry.UsedAt != 0 {
			usedCodes++
		}
	}
	if usedCodes != 1 {
		t.Fatalf("consumed backup codes = %d, want 1", usedCodes)
	}
}

func TestGetEnrollment_InvalidJSON(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	key := enrollPrefix + "badjson"
	if err := st.rdb.Set(ctx, key, "not-json", 10*time.Minute).Err(); err != nil {
		t.Fatalf("set raw: %v", err)
	}
	got, err := st.GetEnrollment(ctx, "badjson")
	if err == nil {
		t.Errorf("GetEnrollment(invalid JSON) err = nil, got = %v", got)
	}
	if got != nil {
		t.Errorf("GetEnrollment(invalid JSON) should return nil")
	}
}

func TestMarkChallengeUsed_IsChallengeUsed(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	if err := st.MarkChallengeUsed(ctx, "c_xyz"); err != nil {
		t.Fatalf("MarkChallengeUsed: %v", err)
	}
	used, err := st.IsChallengeUsed(ctx, "c_xyz")
	if err != nil {
		t.Fatalf("IsChallengeUsed: %v", err)
	}
	if !used {
		t.Error("IsChallengeUsed(c_xyz) = false, want true")
	}
	used, _ = st.IsChallengeUsed(ctx, "c_other")
	if used {
		t.Error("IsChallengeUsed(c_other) = true, want false")
	}
}

func TestClaimChallenge(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	claimed, err := st.ClaimChallenge(ctx, "c_once")
	if err != nil || !claimed {
		t.Fatalf("first ClaimChallenge = (%v, %v), want true", claimed, err)
	}
	claimed, err = st.ClaimChallenge(ctx, "c_once")
	if err != nil || claimed {
		t.Fatalf("second ClaimChallenge = (%v, %v), want false", claimed, err)
	}
}

func TestIncrRateSubject_IncrRateIP(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	n, err := st.IncrRateSubject(ctx, "user1")
	if err != nil {
		t.Fatalf("IncrRateSubject: %v", err)
	}
	if n != 1 {
		t.Errorf("IncrRateSubject = %d, want 1", n)
	}
	n, _ = st.IncrRateSubject(ctx, "user1")
	if n != 2 {
		t.Errorf("IncrRateSubject second = %d, want 2", n)
	}
	mr.FastForward(30 * time.Minute)
	n, err = st.IncrRateSubject(ctx, "user1")
	if err != nil || n != 3 {
		t.Fatalf("IncrRateSubject after 30m = (%d, %v), want 3", n, err)
	}
	if ttl := mr.TTL(rateSubjectPrefix + "user1"); ttl != 30*time.Minute {
		t.Fatalf("subject rate TTL = %v, want 30m (must not be extended)", ttl)
	}
	mr.FastForward(31 * time.Minute)
	n, err = st.IncrRateSubject(ctx, "user1")
	if err != nil || n != 1 {
		t.Fatalf("IncrRateSubject after window = (%d, %v), want reset to 1", n, err)
	}
	n, err = st.IncrRateIP(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("IncrRateIP: %v", err)
	}
	if n != 1 {
		t.Errorf("IncrRateIP = %d, want 1", n)
	}
}

func TestSaveGetBackupCodes_ConsumeBackupCode(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	entries := []BackupCodeEntry{
		{CodeHash: "hash1", UsedAt: 0},
		{CodeHash: "hash2", UsedAt: 0},
	}
	if err := st.SaveBackupCodes(ctx, "user1", entries); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}
	got, err := st.GetBackupCodes(ctx, "user1")
	if err != nil {
		t.Fatalf("GetBackupCodes: %v", err)
	}
	if len(got) != 2 || got[0].CodeHash != "hash1" {
		t.Errorf("GetBackupCodes = %+v", got)
	}
	got, _ = st.GetBackupCodes(ctx, "nobody")
	if got != nil {
		t.Errorf("GetBackupCodes(nobody) = %v, want nil", got)
	}

	consumed, err := st.ConsumeBackupCode(ctx, "user1", "hash1")
	if err != nil {
		t.Fatalf("ConsumeBackupCode: %v", err)
	}
	if !consumed {
		t.Error("ConsumeBackupCode(hash1) = false, want true")
	}
	consumed, _ = st.ConsumeBackupCode(ctx, "user1", "hash1")
	if consumed {
		t.Error("ConsumeBackupCode(hash1) again should be false (already used)")
	}
	consumed, _ = st.ConsumeBackupCode(ctx, "user1", "hash_unknown")
	if consumed {
		t.Error("ConsumeBackupCode(unknown) = true, want false")
	}
	consumed, _ = st.ConsumeBackupCode(ctx, "nobody", "hash1")
	if consumed {
		t.Error("ConsumeBackupCode(nobody) = true, want false")
	}
}

func TestConsumeBackupCode_Concurrent(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	if err := st.SaveBackupCodes(ctx, "concurrent-user", []BackupCodeEntry{{CodeHash: "hash-once"}}); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}

	const workers = 16
	start := make(chan struct{})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			consumed, err := st.ConsumeBackupCode(ctx, "concurrent-user", "hash-once")
			if err != nil {
				t.Errorf("ConsumeBackupCode: %v", err)
				return
			}
			if consumed {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful consumptions = %d, want 1", got)
	}
}

func TestDeleteCredential_DeleteBackupCodes(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()

	cred := &Credential{
		Subject: "del1", SecretEnc: "enc", Issuer: "Herald", Label: "del1",
		Period: 30, Digits: 6, Algo: "SHA1", Enabled: true,
		LastUsedStep: 0, CreatedAt: 1, UpdatedAt: 1,
	}
	if err := st.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if err := st.DeleteCredential(ctx, "del1"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	got, _ := st.GetCredential(ctx, "del1")
	if got != nil {
		t.Errorf("GetCredential after Delete = %v, want nil", got)
	}

	entries := []BackupCodeEntry{{CodeHash: "h1", UsedAt: 0}}
	if err := st.SaveBackupCodes(ctx, "del2", entries); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}
	if err := st.DeleteBackupCodes(ctx, "del2"); err != nil {
		t.Fatalf("DeleteBackupCodes: %v", err)
	}
	gotEntries, _ := st.GetBackupCodes(ctx, "del2")
	if gotEntries != nil {
		t.Errorf("GetBackupCodes after Delete = %v, want nil", gotEntries)
	}
}

func TestDeleteSubject(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	credential := &Credential{Subject: "delete-subject", SecretEnc: "enc", Enabled: true}
	if err := st.SaveCredential(ctx, credential); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if err := st.SaveBackupCodes(ctx, credential.Subject, []BackupCodeEntry{{CodeHash: "hash"}}); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}
	if err := st.DeleteSubject(ctx, credential.Subject); err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}
	if got, _ := st.GetCredential(ctx, credential.Subject); got != nil {
		t.Fatalf("credential after DeleteSubject = %+v", got)
	}
	if got, _ := st.GetBackupCodes(ctx, credential.Subject); got != nil {
		t.Fatalf("backup codes after DeleteSubject = %+v", got)
	}
}

func TestGetCredential_InvalidJSON(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	key := credPrefix + "badjson"
	if err := st.rdb.Set(ctx, key, "not-json", 0).Err(); err != nil {
		t.Fatalf("set raw: %v", err)
	}
	got, err := st.GetCredential(ctx, "badjson")
	if err == nil {
		t.Errorf("GetCredential(invalid JSON) err = nil, got = %v", got)
	}
	if got != nil {
		t.Errorf("GetCredential(invalid JSON) should return nil credential")
	}
}

func TestGetBackupCodes_InvalidJSON(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	key := backupPrefix + "badjson"
	if err := st.rdb.Set(ctx, key, "not-json", 0).Err(); err != nil {
		t.Fatalf("set raw: %v", err)
	}
	got, err := st.GetBackupCodes(ctx, "badjson")
	if err == nil {
		t.Errorf("GetBackupCodes(invalid JSON) err = nil, got = %v", got)
	}
	if got != nil {
		t.Errorf("GetBackupCodes(invalid JSON) should return nil")
	}
}

func TestSaveCredential_WithTTL(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	st.credTTL = 15 * time.Minute

	credential := &Credential{Subject: "expiring", SecretEnc: "enc", Enabled: true}
	if err := st.SaveCredential(context.Background(), credential); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if ttl := mr.TTL(credPrefix + credential.Subject); ttl != st.credTTL {
		t.Fatalf("credential TTL = %v, want %v", ttl, st.credTTL)
	}
}

func TestTransactionalMethods_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		key  string
		call func(*Store) error
	}{
		{
			name: "claim credential step",
			key:  credPrefix + "bad-credential",
			call: func(st *Store) error {
				_, err := st.ClaimCredentialStep(ctx, "bad-credential", 1, 1)
				return err
			},
		},
		{
			name: "confirm enrollment",
			key:  enrollPrefix + "bad-enrollment",
			call: func(st *Store) error {
				_, err := st.ConfirmEnrollment(ctx,
					&Enrollment{EnrollID: "bad-enrollment", Subject: "user", SecretEnc: "enc"},
					&Credential{Subject: "user", SecretEnc: "enc"}, nil)
				return err
			},
		},
		{
			name: "consume backup code",
			key:  backupPrefix + "bad-backup",
			call: func(st *Store) error {
				_, err := st.ConsumeBackupCode(ctx, "bad-backup", "hash")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, mr := newTestStore(t)
			defer mr.Close()
			if err := st.rdb.Set(ctx, tt.key, "not-json", 0).Err(); err != nil {
				t.Fatalf("seed invalid JSON: %v", err)
			}
			if err := tt.call(st); err == nil {
				t.Fatal("expected JSON decoding error")
			}
		})
	}
}

func TestConfirmEnrollment_MismatchedState(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	stored := &Enrollment{EnrollID: "mismatch", Subject: "user", SecretEnc: "stored"}
	if err := st.SaveEnrollment(ctx, stored); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	confirmed, err := st.ConfirmEnrollment(ctx,
		&Enrollment{EnrollID: stored.EnrollID, Subject: stored.Subject, SecretEnc: "different"},
		&Credential{Subject: stored.Subject, SecretEnc: "different"}, nil)
	if err != nil || confirmed {
		t.Fatalf("ConfirmEnrollment = (%v, %v), want (false, nil)", confirmed, err)
	}
	if got, err := st.GetEnrollment(ctx, stored.EnrollID); err != nil || got == nil {
		t.Fatalf("mismatched enrollment was consumed: (%+v, %v)", got, err)
	}
}

func TestStore_RedisErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func(*Store) error
	}{
		{name: "save credential", call: func(st *Store) error { return st.SaveCredential(ctx, &Credential{Subject: "user"}) }},
		{name: "get credential", call: func(st *Store) error { _, err := st.GetCredential(ctx, "user"); return err }},
		{name: "delete credential", call: func(st *Store) error { return st.DeleteCredential(ctx, "user") }},
		{name: "delete backup codes", call: func(st *Store) error { return st.DeleteBackupCodes(ctx, "user") }},
		{name: "delete subject", call: func(st *Store) error { return st.DeleteSubject(ctx, "user") }},
		{name: "save enrollment", call: func(st *Store) error { return st.SaveEnrollment(ctx, &Enrollment{EnrollID: "enroll"}) }},
		{name: "get enrollment", call: func(st *Store) error { _, err := st.GetEnrollment(ctx, "enroll"); return err }},
		{name: "delete enrollment", call: func(st *Store) error { return st.DeleteEnrollment(ctx, "enroll") }},
		{name: "confirm enrollment", call: func(st *Store) error {
			_, err := st.ConfirmEnrollment(ctx, &Enrollment{EnrollID: "enroll"}, &Credential{Subject: "user"}, nil)
			return err
		}},
		{name: "mark challenge", call: func(st *Store) error { return st.MarkChallengeUsed(ctx, "challenge") }},
		{name: "claim challenge", call: func(st *Store) error { _, err := st.ClaimChallenge(ctx, "challenge"); return err }},
		{name: "check challenge", call: func(st *Store) error { _, err := st.IsChallengeUsed(ctx, "challenge"); return err }},
		{name: "increment subject rate", call: func(st *Store) error { _, err := st.IncrRateSubject(ctx, "user"); return err }},
		{name: "increment IP rate", call: func(st *Store) error { _, err := st.IncrRateIP(ctx, "127.0.0.1"); return err }},
		{name: "save backup codes", call: func(st *Store) error { return st.SaveBackupCodes(ctx, "user", nil) }},
		{name: "get backup codes", call: func(st *Store) error { _, err := st.GetBackupCodes(ctx, "user"); return err }},
		{name: "consume backup code", call: func(st *Store) error { _, err := st.ConsumeBackupCode(ctx, "user", "hash"); return err }},
		{name: "claim credential step", call: func(st *Store) error { _, err := st.ClaimCredentialStep(ctx, "user", 1, 1); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, mr := newTestStore(t)
			defer mr.Close()
			mr.SetError("ERR injected failure")
			if err := tt.call(st); err == nil {
				t.Fatal("expected Redis error")
			}
		})
	}
}
