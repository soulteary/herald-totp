package store

import (
	"context"
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
	_ = st.DeleteEnrollment(ctx, "e_abc")
	got, _ = st.GetEnrollment(ctx, "e_abc")
	if got != nil {
		t.Errorf("GetEnrollment after Delete = %v, want nil", got)
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
