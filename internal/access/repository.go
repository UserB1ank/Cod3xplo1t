package access

import (
	"context"
	"errors"
	"time"
)

// ErrTooManySessions reports that the installation already holds the maximum
// number of live login sessions.
var ErrTooManySessions = errors.New("登录会话数量已达上限，请先退出其他会话")

// Account is the password digest the identity repository stores. It never
// contains a plaintext password.
type Account struct {
	Username   string `json:"username"`
	Salt       []byte `json:"salt"`
	Hash       []byte `json:"password_hash"`
	Iterations int    `json:"iterations"`
}

// Session is a revocable login session keyed by the SHA-256 digest of its
// bearer token. Only the digest is persisted.
type Session struct {
	TokenHash []byte
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Repository persists the administrator account, revocable sessions and login
// rate-limit windows. Implementations must make CreateAccount exclusive and
// AllowAttempt atomic across processes.
type Repository interface {
	LoadAccount(context.Context) (Account, bool, error)
	CreateAccount(context.Context, Account) error

	CreateSession(context.Context, Session) error
	LoadSession(context.Context, []byte) (Session, bool, error)
	DeleteSession(context.Context, []byte) error

	// AllowAttempt records one login/setup attempt for a pseudonymous peer key
	// and reports whether it is within the limit. The returned time is when the
	// current window ends.
	AllowAttempt(context.Context, string, time.Time) (bool, time.Time, error)
	ResetAttempts(context.Context, string) error
}
