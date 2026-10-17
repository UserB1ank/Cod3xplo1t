package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/testgit"
)

func TestRemoteGitSnapshotCanStartFromTagAndReuseCommit(t *testing.T) {
	t.Parallel()
	remote := testgit.New(t, "")
	commit := remote.Commit(t, "package main\nconst version = 1\n")
	remote.Git(t, "tag", "release-1")
	remote.Git(t, "update-server-info")
	manager := newTestManager(t)
	manager.AllowNetwork, manager.GitCAFile = true, remote.CAFile
	input := Source{Kind: KindRemoteGit, Raw: remote.URL, Ref: "release-1"}
	snapshot, err := manager.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, manager, snapshot.SnapshotID)
	contents, err := os.ReadFile(filepath.Join(snapshot.TreeDir(), "main.go"))
	if err != nil || string(contents) != "package main\nconst version = 1\n" || snapshot.Commit != commit || snapshot.RequestedRef != "release-1" {
		t.Fatalf("tag was not pinned to its source: snapshot=%+v contents=%q error=%v", snapshot, contents, err)
	}
	input.Ref = commit
	reused, err := manager.Create(context.Background(), input)
	if err != nil || reused.SnapshotID != snapshot.SnapshotID {
		t.Fatalf("commit did not reuse tag snapshot: %v %v", reused, err)
	}
}

func TestRemoteGitCredentialIsBoundToProjectAndOrigin(t *testing.T) {
	t.Parallel()
	const authorization = "Bearer synthetic-repository-fixture"
	remote := testgit.New(t, authorization)
	remote.Commit(t, "package main\n")
	credentialFile := filepath.Join(t.TempDir(), "credential.json")
	document, err := json.Marshal(map[string]any{"origin": remote.Server.URL, "project_ids": []string{"proj-owner"}, "authorization": authorization})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialFile, document, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(filepath.Join(t.TempDir(), "workspace"), WithAllowNetwork(true), WithGitCAFile(remote.CAFile), WithGitCredentialFiles(map[string]string{"repository-fixture": credentialFile}))
	if err != nil {
		t.Fatal(err)
	}
	input := Source{Kind: KindRemoteGit, Raw: remote.URL, Ref: "main", ProjectID: "proj-owner", CredentialRef: "repository-fixture"}
	snapshot, err := manager.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("authorized capture: %v", err)
	}
	cleanup(t, manager, snapshot.SnapshotID)
	public, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(public), authorization) || strings.Contains(string(public), credentialFile) {
		t.Fatalf("credential leaked into metadata: %v", err)
	}
	input.ProjectID = "proj-other"
	if _, err := manager.Create(context.Background(), input); !errors.Is(err, ErrGitAccessDenied) {
		t.Fatalf("cross-project credential accepted: %v", err)
	}
	input.ProjectID, input.Raw = "proj-owner", "https://other.example.invalid/service.git"
	if _, err := manager.Create(context.Background(), input); !errors.Is(err, ErrGitAccessDenied) {
		t.Fatalf("cross-origin credential accepted: %v", err)
	}
}

func TestRemoteSSHDefinitionRequiresProjectCredentialAndKnownHosts(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	manager := newTestManager(t)
	input := Source{Kind: KindRemoteGit, Raw: "ssh://forge.example.invalid/team/service.git", Ref: "main", ProjectID: "proj-owner"}
	if err := manager.ValidateGitSource(input); !errors.Is(err, ErrGitCredential) {
		t.Fatalf("SSH without pinned host credentials accepted: %v", err)
	}
	key, hosts := filepath.Join(directory, "identity"), filepath.Join(directory, "known_hosts")
	for _, file := range []string{key, hosts} {
		if err := os.WriteFile(file, []byte("synthetic configuration fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	credentialFile := filepath.Join(directory, "credential.json")
	document, err := json.Marshal(map[string]any{"origin": "ssh://forge.example.invalid", "project_ids": []string{"proj-owner"}, "ssh_user": "git", "ssh_identity_file": key, "ssh_known_hosts_file": hosts})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialFile, document, 0o600); err != nil {
		t.Fatal(err)
	}
	manager.GitCredentialFiles = map[string]string{"ssh-fixture": credentialFile}
	input.CredentialRef = "ssh-fixture"
	if err := manager.ValidateGitSource(input); err != nil {
		t.Fatalf("registered SSH definition rejected: %v", err)
	}
	if err := os.Remove(hosts); err != nil {
		t.Fatal(err)
	}
	if err := manager.ValidateGitSource(input); !errors.Is(err, ErrGitCredential) {
		t.Fatalf("missing known_hosts accepted: %v", err)
	}
}

func TestRemoteGitHeadTracksTheCurrentDefaultBranch(t *testing.T) {
	t.Parallel()
	remote := testgit.New(t, "")
	first := remote.Commit(t, "package main\nconst version = 1\n")
	remote.Git(t, "checkout", "-q", "-b", "next")
	second := remote.Commit(t, "package main\nconst version = 2\n")
	remote.Git(t, "symbolic-ref", "HEAD", "refs/heads/main")
	remote.Git(t, "update-server-info")
	manager := newTestManager(t)
	manager.AllowNetwork, manager.GitCAFile = true, remote.CAFile
	input := Source{Kind: KindRemoteGit, Raw: remote.URL, Ref: "HEAD"}
	original, err := manager.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, manager, original.SnapshotID)
	if original.Commit != first {
		t.Fatalf("initial HEAD = %s, want %s", original.Commit, first)
	}
	remote.Git(t, "symbolic-ref", "HEAD", "refs/heads/next")
	updated, err := manager.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, manager, updated.SnapshotID)
	if updated.Commit != second {
		t.Fatalf("remote HEAD stayed on the previous default branch: %s", updated.Commit)
	}
}

func TestRemoteGitConcurrentCapturesKeepTargetsReadOnly(t *testing.T) {
	t.Parallel()
	remote := testgit.New(t, "")
	marker := filepath.Join(t.TempDir(), "target-executed")
	// Git's shell is available on all platforms supported by the Git fixture.
	script := "#!/bin/sh\nprintf executed > '" + strings.ReplaceAll(filepath.ToSlash(marker), "'", "'\\''") + "'\n"
	for _, name := range []string{"build.sh", ".git/hooks/post-checkout"} {
		if err := os.WriteFile(filepath.Join(remote.Dir, filepath.FromSlash(name)), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(remote.Dir, "Makefile"), []byte("all:\n\tsh build.sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commit := remote.Commit(t, "package main\n")
	manager := newTestManager(t)
	manager.AllowNetwork, manager.GitCAFile = true, remote.CAFile
	var wait sync.WaitGroup
	results := make(chan *Snapshot, 2)
	failures := make(chan error, 2)
	for _, identity := range []string{"project-a/source", "project-b/source"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			snapshot, err := manager.Create(context.Background(), Source{Kind: KindRemoteGit, Raw: remote.URL, Ref: "main", NameOverride: identity})
			if err != nil {
				failures <- err
				return
			}
			results <- snapshot
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	ids := map[string]bool{}
	for snapshot := range results {
		cleanup(t, manager, snapshot.SnapshotID)
		ids[snapshot.SnapshotID] = true
		if snapshot.Commit != commit {
			t.Fatalf("capture moved commit: %s", snapshot.Commit)
		}
	}
	for err := range failures {
		t.Errorf("concurrent capture: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("project snapshots were merged or missing: %v", ids)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target hook or build ran: %v", err)
	}
}
