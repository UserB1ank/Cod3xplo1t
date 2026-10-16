package repository

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultLimitsAreValid(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	if err := l.Validate(); err != nil {
		t.Fatalf("default limits are invalid: %v", err)
	}
	if !reflect.DeepEqual(l.WithDefaults(), l) {
		t.Fatal("WithDefaults changed a fully populated value")
	}
	zero := Limits{}
	if got := zero.WithDefaults(); !reflect.DeepEqual(got, l) {
		t.Fatalf("zero limits did not fall back to defaults: %+v", got)
	}
}

func TestLimitsValidateRejectsBadValues(t *testing.T) {
	t.Parallel()
	cases := map[string]Limits{
		"negative bytes":   {MaxRepoBytes: -1},
		"negative files":   {MaxFiles: -1},
		"symlink policy":   {Symlinks: "follow"},
		"submodule policy": {Submodules: "expand"},
		"lfs policy":       {LFS: "fetch"},
	}
	for name, l := range cases {
		if err := l.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestIgnoreMatcherDefaultsAndOverrides(t *testing.T) {
	t.Parallel()
	m := newIgnoreMatcher(DefaultLimits())
	ignored := []string{"node_modules/dep/index.js", "dist/bundle.js", "a/b/vendor/c.go", ".git/config", "app.min.js"}
	for _, p := range ignored {
		ok, rule := m.Match(p, false)
		if !ok {
			t.Errorf("%s: expected to be ignored", p)
			continue
		}
		if rule == "" {
			t.Errorf("%s: ignored without an explaining rule", p)
		}
	}
	kept := []string{"main.go", "internal/app/service.go", "vendor.go", "go.sum", "package-lock.json"}
	for _, p := range kept {
		if ok, rule := m.Match(p, false); ok {
			t.Errorf("%s: unexpectedly ignored by %s", p, rule)
		}
	}
}

func TestIgnoreMatcherExplicitInclude(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	l.IncludeIgnoredDirs = []string{"vendor", "dist/"}
	l.ExtraIgnoreDirs = []string{"generated/", "*.snap"}
	m := newIgnoreMatcher(l)

	if ok, rule := m.Match("vendor/lib.go", false); ok {
		t.Errorf("explicit include did not override the default rule (%s)", rule)
	}
	if ok, rule := m.Match("dist/app.js", false); ok {
		t.Errorf("explicit include did not override the default rule (%s)", rule)
	}
	if ok, _ := m.Match("node_modules/dep/index.js", false); !ok {
		t.Error("overriding one directory must not re-enable the others")
	}
	for _, p := range []string{"generated/code.go", "logs/app.snap"} {
		if ok, _ := m.Match(p, false); !ok {
			t.Errorf("%s: extra ignore rule not applied", p)
		}
	}
	if ok, _ := m.Match("app.snapshot", false); ok {
		t.Error("glob rule matched a non-matching name")
	}
}

func TestIsBinary(t *testing.T) {
	t.Parallel()
	if IsBinary([]byte("package main\n")) {
		t.Error("text detected as binary")
	}
	if !IsBinary([]byte{0x7f, 'E', 'L', 'F', 0x00, 0x01}) {
		t.Error("NUL byte not detected as binary")
	}
	if IsBinary(nil) {
		t.Error("empty content reported as binary")
	}
}

func TestReadPrefixLimitsSniffing(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte("a"), binarySniffSize*2)
	got, err := readPrefix(bytes.NewReader(big))
	if err != nil {
		t.Fatalf("readPrefix: %v", err)
	}
	if len(got) != binarySniffSize {
		t.Fatalf("readPrefix returned %d bytes, want %d", len(got), binarySniffSize)
	}
	if _, err := readPrefix(strings.NewReader("short")); err != nil {
		t.Fatalf("readPrefix on short input: %v", err)
	}
}
