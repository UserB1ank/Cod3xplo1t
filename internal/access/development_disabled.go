//go:build !dev

package access

// DevelopmentBuild is false in builds without the dev tag.
const DevelopmentBuild = false

func developmentCredentials(username, password string) bool { return false }
