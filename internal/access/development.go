//go:build dev

package access

import "crypto/subtle"

// DevelopmentBuild enables the default administrator only in dev binaries.
const DevelopmentBuild = true

func developmentCredentials(username, password string) bool {
	return subtle.ConstantTimeCompare([]byte(username), []byte("devadmin"))&subtle.ConstantTimeCompare([]byte(password), []byte("devadmin")) == 1
}
