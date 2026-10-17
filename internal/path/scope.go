package path

import "strings"

// InScope matches whole path components, so internal/api never matches api2.
func InScope(file string, prefixes []string) bool {
	file = strings.ReplaceAll(file, "\\", "/")
	for _, prefix := range prefixes {
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix == "." || file == prefix || strings.HasPrefix(file, prefix+"/") {
			return true
		}
	}
	return len(prefixes) == 0
}
