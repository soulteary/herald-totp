package store

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	credPrefix          = "totp:cred:"
	enrollPrefix        = "totp:enroll:"
	enrollSubjectPrefix = "totp:enroll_subject:"
	backupPrefix        = "totp:backup:"
	chUsedPrefix        = "totp:ch_used:"
	rateSubjectPrefix   = "totp:rate:subject:"
	rateIPPrefix        = "totp:rate:ip:"
	transactionRetries  = 16
)

var (
	// ErrCredentialExists is returned when enrollment would replace an
	// existing credential.
	ErrCredentialExists = errors.New("credential already exists")
	// ErrEnrollmentInProgress is returned when a subject already has a live
	// enrollment awaiting confirmation.
	ErrEnrollmentInProgress = errors.New("enrollment already in progress")
)

var incrementRateScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count
`)

var saveEnrollmentScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[2]) == 1 then
  return 0
end
if redis.call("EXISTS", KEYS[3]) == 1 then
  return -1
end
redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2])
redis.call("SET", KEYS[3], ARGV[3], "PX", ARGV[2])
return 1
`)

var deleteSubjectScript = redis.NewScript(`
local enrollID = redis.call("GET", KEYS[3])
if enrollID then
  redis.call("DEL", ARGV[1] .. enrollID)
end
return redis.call("DEL", KEYS[1], KEYS[2], KEYS[3])
`)

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

// DeleteSubject atomically removes a subject's credential and backup codes.
func (s *Store) DeleteSubject(ctx context.Context, subject string) error {
	return deleteSubjectScript.Run(ctx, s.rdb, []string{
		credPrefix + subject,
		backupPrefix + subject,
		enrollSubjectPrefix + subject,
	}, enrollPrefix).Err()
}

// SaveEnrollment saves a temporary enrollment; TTL is applied.
func (s *Store) SaveEnrollment(ctx context.Context, e *Enrollment) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	result, err := saveEnrollmentScript.Run(ctx, s.rdb, []string{
		enrollPrefix + e.EnrollID,
		credPrefix + e.Subject,
		enrollSubjectPrefix + e.Subject,
	}, data, s.enrollTTL.Milliseconds(), e.EnrollID).Int64()
	if err != nil {
		return err
	}
	switch result {
	case 0:
		return ErrCredentialExists
	case -1:
		return ErrEnrollmentInProgress
	default:
		return nil
	}
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

// ConfirmEnrollment atomically persists the credential and backup codes and
// consumes the temporary enrollment. It returns false when another request has
// already consumed or replaced the enrollment.
func (s *Store) ConfirmEnrollment(ctx context.Context, enrollment *Enrollment, credential *Credential, entries []BackupCodeEntry) (bool, error) {
	credentialData, err := json.Marshal(credential)
	if err != nil {
		return false, err
	}
	backupData, err := json.Marshal(entries)
	if err != nil {
		return false, err
	}

	enrollmentKey := enrollPrefix + enrollment.EnrollID
	credentialKey := credPrefix + credential.Subject
	backupKey := backupPrefix + credential.Subject
	enrollmentSubjectKey := enrollSubjectPrefix + credential.Subject
	for range transactionRetries {
		confirmed := false
		credentialExists := false
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, enrollmentKey).Bytes()
			if err == redis.Nil {
				return nil
			}
			if err != nil {
				return err
			}
			var current Enrollment
			if err := json.Unmarshal(data, &current); err != nil {
				return err
			}
			if current.EnrollID != enrollment.EnrollID || current.Subject != enrollment.Subject || current.SecretEnc != enrollment.SecretEnc {
				return nil
			}
			activeEnrollID, err := tx.Get(ctx, enrollmentSubjectKey).Result()
			if err != nil && err != redis.Nil {
				return err
			}
			// Deployments before the subject index was introduced may still
			// have valid main enrollment records. A missing index is compatible:
			// because this key is watched, any concurrent newer enrollment that
			// creates the index aborts this transaction before commit.
			if err == nil && activeEnrollID != enrollment.EnrollID {
				return nil
			}
			exists, err := tx.Exists(ctx, credentialKey).Result()
			if err != nil {
				return err
			}
			if exists > 0 {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, enrollmentKey, enrollmentSubjectKey)
					return nil
				})
				credentialExists = err == nil
				return err
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, credentialKey, credentialData, s.credTTL)
				pipe.Set(ctx, backupKey, backupData, 0)
				pipe.Del(ctx, enrollmentKey, enrollmentSubjectKey)
				return nil
			})
			if err == nil {
				confirmed = true
			}
			return err
		}, enrollmentKey, enrollmentSubjectKey, credentialKey)
		if err == redis.TxFailedErr {
			continue
		}
		if err != nil {
			return false, err
		}
		if credentialExists {
			return false, ErrCredentialExists
		}
		return confirmed, nil
	}
	return false, redis.TxFailedErr
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
	return s.incrementRate(ctx, rateSubjectPrefix+subject, s.rateSubTTL)
}

// IncrRateIP increments IP rate counter; returns new count.
func (s *Store) IncrRateIP(ctx context.Context, ip string) (int64, error) {
	return s.incrementRate(ctx, rateIPPrefix+ip, s.rateIPTTL)
}

func (s *Store) incrementRate(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return incrementRateScript.Run(ctx, s.rdb, []string{key}, ttl.Milliseconds()).Int64()
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
