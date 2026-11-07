package store

import (
	"context"
	"encoding/json"
	"github.com/redis/go-redis/v9"
	"sync"
	"testing"
)

func TestValidatedClaimPreservesChangedCredentialAndUnusedChallenge(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Credential)
	}{
		{"replacement secret", func(c *Credential) { c.SecretEnc = "replacement" }},
		{"replacement creation time", func(c *Credential) { c.CreatedAt++ }},
		{"disabled credential", func(c *Credential) { c.Enabled = false }},
		{"different subject", func(c *Credential) { c.Subject = "other" }},
		{"changed period", func(c *Credential) { c.Period = 60 }},
		{"changed digits", func(c *Credential) { c.Digits = 8 }},
		{"changed algorithm", func(c *Credential) { c.Algo = "SHA256" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, mr := newTestStore(t)
			defer mr.Close()
			ctx := context.Background()
			snapshot := Credential{Subject: "snapshot-user", SecretEnc: "original", Enabled: true, Period: 30, Digits: 6, Algo: "SHA1", CreatedAt: 1, UpdatedAt: 1, LastUsedStep: 1}
			current := snapshot
			tc.change(&current)
			encoded, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			if err = st.rdb.Set(ctx, credPrefix+snapshot.Subject, encoded, 0).Err(); err != nil {
				t.Fatal(err)
			}
			before := mr.Dump()
			claimed, err := st.ClaimValidatedCredentialStepAndChallenge(ctx, snapshot.Subject, &snapshot, 3, 3, "unchanged-challenge")
			if err != nil || claimed {
				t.Fatalf("changed credential claim=(%v,%v)", claimed, err)
			}
			if mr.Dump() != before {
				t.Fatal("stale validation changed credential or consumed challenge")
			}
		})
	}
}

func TestValidatedClaimAllowsCounterProgressForSameCredential(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	snapshot := Credential{Subject: "snapshot-user", SecretEnc: "original", Enabled: true, Period: 30, Digits: 6, Algo: "SHA1", CreatedAt: 1, UpdatedAt: 1, LastUsedStep: 1}
	current := snapshot
	current.LastUsedStep = 2
	current.UpdatedAt = 2
	current.Label = "updated display label"
	if err := st.SaveCredential(ctx, &current); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimValidatedCredentialStepAndChallenge(ctx, snapshot.Subject, &snapshot, 3, 3, "new-challenge")
	if err != nil || !claimed {
		t.Fatalf("same credential claim=(%v,%v)", claimed, err)
	}
	stored, err := st.GetCredential(ctx, snapshot.Subject)
	if err != nil || stored == nil || stored.LastUsedStep != 3 || stored.UpdatedAt != 3 || stored.Label != current.Label {
		t.Fatalf("unexpected committed credential: %+v %v", stored, err)
	}
	used, err := st.IsChallengeUsed(ctx, "new-challenge")
	if err != nil || !used {
		t.Fatalf("challenge claim=(%v,%v)", used, err)
	}
	before := mr.Dump()
	claimed, err = st.ClaimValidatedCredentialStepAndChallenge(ctx, snapshot.Subject, &snapshot, 4, 4, "new-challenge")
	if err != nil || claimed || mr.Dump() != before {
		t.Fatalf("duplicate challenge changed state: %v %v", claimed, err)
	}
}

func TestValidatedClaimRequiresEnabledMatchingSnapshot(t *testing.T) {
	for _, scenario := range []string{"nil", "disabled", "other subject"} {
		t.Run(scenario, func(t *testing.T) {
			st, mr := newTestStore(t)
			defer mr.Close()
			snapshot := &Credential{Subject: "user", Enabled: true}
			switch scenario {
			case "nil":
				snapshot = nil
			case "disabled":
				snapshot.Enabled = false
			case "other subject":
				snapshot.Subject = "other"
			}
			claimed, err := st.ClaimValidatedCredentialStepAndChallenge(context.Background(), "user", snapshot, 1, 1, "unused")
			if err != nil || claimed || len(mr.Keys()) != 0 {
				t.Fatalf("invalid snapshot claim=(%v,%v), keys=%v", claimed, err, mr.Keys())
			}
		})
	}
}

type replaceSnapshotBeforeCommit struct {
	once    sync.Once
	replace func() error
}

func (h *replaceSnapshotBeforeCommit) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *replaceSnapshotBeforeCommit) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}
func (h *replaceSnapshotBeforeCommit) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, commands []redis.Cmder) error {
		if len(commands) > 0 && commands[0].Name() == "multi" {
			var err error
			h.once.Do(func() { err = h.replace() })
			if err != nil {
				return err
			}
		}
		return next(ctx, commands)
	}
}

func TestValidatedClaimRechecksSnapshotAfterTransactionConflict(t *testing.T) {
	st, mr := newTestStore(t)
	defer mr.Close()
	ctx := context.Background()
	snapshot := Credential{Subject: "snapshot-user", SecretEnc: "original", Enabled: true, Period: 30, Digits: 6, Algo: "SHA1", CreatedAt: 1, LastUsedStep: 1}
	if err := st.SaveCredential(ctx, &snapshot); err != nil {
		t.Fatal(err)
	}
	replacement := snapshot
	replacement.SecretEnc = "replacement"
	writer := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	st.rdb.AddHook(&replaceSnapshotBeforeCommit{replace: func() error {
		data, err := json.Marshal(replacement)
		if err != nil {
			return err
		}
		return writer.Set(ctx, credPrefix+snapshot.Subject, data, 0).Err()
	}})
	claimed, err := st.ClaimValidatedCredentialStepAndChallenge(ctx, snapshot.Subject, &snapshot, 3, 3, "unchanged-challenge")
	if err != nil || claimed {
		t.Fatalf("retry claim=(%v,%v)", claimed, err)
	}
	stored, err := st.GetCredential(ctx, snapshot.Subject)
	if err != nil || stored == nil || *stored != replacement {
		t.Fatalf("retry changed replacement: %+v %v", stored, err)
	}
	used, err := st.IsChallengeUsed(ctx, "unchanged-challenge")
	if err != nil || used {
		t.Fatalf("retry challenge=(%v,%v)", used, err)
	}
}
