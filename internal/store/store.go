package store

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	credPrefix         = "totp:cred:"
	enrollPrefix       = "totp:enroll:"
	backupPrefix       = "totp:backup:"
	chUsedPrefix       = "totp:ch_used:"
	rateSubjectPrefix  = "totp:rate:subject:"
	rateIPPrefix       = "totp:rate:ip:"
	transactionRetries = 16
)

// Credential is the persisted TOTP credential for a subject.
type Credential struct {
	Subject      string `json:"subject"`
	SecretEnc    string `json:"secret_enc"`
	Issuer       string `json:"issuer"`
	Label        string `json:"label"`
	Period       uint   `json:"period"`
	Digits       int    `json:"digits"`
	Algo         string `json:"algo"`
	Enabled      bool   `json:"enabled"`
	LastUsedStep int64  `json:"last_used_step"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// Enrollment is the temporary enrollment state.
type Enrollment struct {
	EnrollID  string `json:"enroll_id"`
	Subject   string `json:"subject"`
	SecretEnc string `json:"secret_enc"`
	Issuer    string `json:"issuer"`
	Label     string `json:"label"`
	Period    uint   `json:"period"`
	Digits    int    `json:"digits"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

// BackupCodeEntry is a single backup code (hash only stored).
type BackupCodeEntry struct {
	CodeHash string `json:"code_hash"`
	UsedAt   int64  `json:"used_at"` // 0 = not used
}

// Store handles Redis persistence for credentials, enrollments, backup codes, and rate limits.
type Store struct {
	rdb        *redis.Client
	enrollTTL  time.Duration
	credTTL    time.Duration // 0 = no expiry
	chUsedTTL  time.Duration
	rateSubTTL time.Duration
	rateIPTTL  time.Duration
}

// NewStore creates a Store with the given Redis client and TTLs.
func NewStore(rdb *redis.Client, enrollTTL, credTTL, chUsedTTL, rateSubTTL, rateIPTTL time.Duration) *Store {
	return &Store{
		rdb:        rdb,
		enrollTTL:  enrollTTL,
		credTTL:    credTTL,
		chUsedTTL:  chUsedTTL,
		rateSubTTL: rateSubTTL,
		rateIPTTL:  rateIPTTL,
	}
}

// SaveCredential persists a credential.
func (s *Store) SaveCredential(ctx context.Context, c *Credential) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	key := credPrefix + c.Subject
	if s.credTTL > 0 {
		return s.rdb.Set(ctx, key, data, s.credTTL).Err()
	}
	return s.rdb.Set(ctx, key, data, 0).Err()
}

// ClaimCredentialStep advances a credential's last-used TOTP counter with an
// optimistic Redis transaction. It returns false when the counter was already
// used, so concurrent requests cannot both accept the same TOTP code.
func (s *Store) ClaimCredentialStep(ctx context.Context, subject string, step, updatedAt int64) (bool, error) {
	key := credPrefix + subject
	for range transactionRetries {
		claimed := false
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if err != nil {
				return err
			}
			var credential Credential
			if err := json.Unmarshal(data, &credential); err != nil {
				return err
			}
			if step <= credential.LastUsedStep {
				return nil
			}

			credential.LastUsedStep = step
			credential.UpdatedAt = updatedAt
			encoded, err := json.Marshal(&credential)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, encoded, s.credTTL)
				return nil
			})
			if err == nil {
				claimed = true
			}
			return err
		}, key)
		if err == redis.TxFailedErr {
			continue
		}
		return claimed, err
	}
	return false, redis.TxFailedErr
}

// GetCredential returns the credential for the subject, or nil if not found.
func (s *Store) GetCredential(ctx context.Context, subject string) (*Credential, error) {
	key := credPrefix + subject
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// DeleteCredential removes the credential for the subject.
func (s *Store) DeleteCredential(ctx context.Context, subject string) error {
	return s.rdb.Del(ctx, credPrefix+subject).Err()
}

// DeleteBackupCodes removes backup codes for the subject.
func (s *Store) DeleteBackupCodes(ctx context.Context, subject string) error {
	return s.rdb.Del(ctx, backupPrefix+subject).Err()
}

// SaveEnrollment saves a temporary enrollment; TTL is applied.
func (s *Store) SaveEnrollment(ctx context.Context, e *Enrollment) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	key := enrollPrefix + e.EnrollID
	return s.rdb.Set(ctx, key, data, s.enrollTTL).Err()
}

// GetEnrollment returns the enrollment by enroll_id, or nil if not found/expired.
func (s *Store) GetEnrollment(ctx context.Context, enrollID string) (*Enrollment, error) {
	key := enrollPrefix + enrollID
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e Enrollment
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// DeleteEnrollment removes the enrollment (after confirm).
func (s *Store) DeleteEnrollment(ctx context.Context, enrollID string) error {
	return s.rdb.Del(ctx, enrollPrefix+enrollID).Err()
}

// MarkChallengeUsed records that a challenge_id was used (for replay protection).
func (s *Store) MarkChallengeUsed(ctx context.Context, challengeID string) error {
	key := chUsedPrefix + challengeID
	return s.rdb.Set(ctx, key, "1", s.chUsedTTL).Err()
}

// ClaimChallenge records a challenge ID only if it has not already been used.
func (s *Store) ClaimChallenge(ctx context.Context, challengeID string) (bool, error) {
	key := chUsedPrefix + challengeID
	return s.rdb.SetNX(ctx, key, "1", s.chUsedTTL).Result()
}

// IsChallengeUsed returns true if the challenge was already used.
func (s *Store) IsChallengeUsed(ctx context.Context, challengeID string) (bool, error) {
	key := chUsedPrefix + challengeID
	n, err := s.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// IncrRateSubject increments subject rate counter; returns new count.
func (s *Store) IncrRateSubject(ctx context.Context, subject string) (int64, error) {
	key := rateSubjectPrefix + subject
	pipe := s.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, s.rateSubTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// IncrRateIP increments IP rate counter; returns new count.
func (s *Store) IncrRateIP(ctx context.Context, ip string) (int64, error) {
	key := rateIPPrefix + ip
	pipe := s.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, s.rateIPTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// SaveBackupCodes stores backup code hashes for a subject (JSON array).
func (s *Store) SaveBackupCodes(ctx context.Context, subject string, entries []BackupCodeEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	key := backupPrefix + subject
	return s.rdb.Set(ctx, key, data, 0).Err()
}

// GetBackupCodes returns backup code entries for the subject.
func (s *Store) GetBackupCodes(ctx context.Context, subject string) ([]BackupCodeEntry, error) {
	key := backupPrefix + subject
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []BackupCodeEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// ConsumeBackupCode finds a matching unused backup code by hash, marks it used, returns true.
func (s *Store) ConsumeBackupCode(ctx context.Context, subject string, codeHash string) (bool, error) {
	key := backupPrefix + subject
	for range transactionRetries {
		consumed := false
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if err == redis.Nil {
				return nil
			}
			if err != nil {
				return err
			}
			var entries []BackupCodeEntry
			if err := json.Unmarshal(data, &entries); err != nil {
				return err
			}
			for i := range entries {
				if entries[i].UsedAt != 0 || subtle.ConstantTimeCompare([]byte(entries[i].CodeHash), []byte(codeHash)) != 1 {
					continue
				}
				entries[i].UsedAt = time.Now().Unix()
				encoded, err := json.Marshal(entries)
				if err != nil {
					return err
				}
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Set(ctx, key, encoded, 0)
					return nil
				})
				if err == nil {
					consumed = true
				}
				return err
			}
			return nil
		}, key)
		if err == redis.TxFailedErr {
			continue
		}
		return consumed, err
	}
	return false, redis.TxFailedErr
}
