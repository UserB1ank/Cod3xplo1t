package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledJavaSinkCatalogIsVersionedAndCompleteForFirstSlice(t *testing.T) {
	catalog, digest, err := loadJavaCatalog(filepath.Join("..", "..", "plugins", "joern"))
	if err != nil {
		t.Fatalf("loadJavaCatalog: %v", err)
	}
	if catalog.ID != "java-sink-catalog" || catalog.Version != "1.0.0" || len(catalog.Entries) < 20 || len(digest) != 64 {
		t.Fatalf("catalog identity = %s@%s, entries=%d, digest=%q", catalog.ID, catalog.Version, len(catalog.Entries), digest)
	}
	wanted := map[string]bool{
		"java.process.runtime-exec":             false,
		"java.deserialization.object-input":     false,
		"java.expression.spel":                  false,
		"java.jndi.context-lookup":              false,
		"java.sql.statement-execute-query":      false,
		"java.sql.mybatis-sqlsession-select":    false,
		"java.sql.hibernate-session-query":      false,
		"java.xxe.document-builder":             false,
		"java.network.http-client-send":         false,
		"java.file.file-input-stream-read":      false,
		"java.ldap.dir-context-search":          false,
		"java.template.freemarker-get-template": false,
		"java.template.spring-process":          false,
	}
	for _, entry := range catalog.Entries {
		if _, ok := wanted[entry.ID]; ok {
			wanted[entry.ID] = true
		}
		if entry.Match.ReceiverType == "" || entry.Match.Method == "" || entry.DangerousArguments == nil || len(entry.Limitations) == 0 {
			t.Errorf("incomplete entry: %+v", entry)
		}
	}
	for id, found := range wanted {
		if !found {
			t.Errorf("first-slice Java coverage is missing %s", id)
		}
	}
}

func TestJavaSinkCatalogRejectsAmbiguousAndUnsafeEntries(t *testing.T) {
	base := javaSinkCatalog{
		APIVersion: javaCatalogAPIVersion, ID: "java-sink-catalog", Version: "1.0.0",
		Entries: []javaSinkEntry{{
			ID: "java.test.sink", Category: "deserialization",
			Match:              javaSinkMatch{ReceiverType: "java.io.ObjectInputStream", Method: "readObject", MatchType: "exact"},
			DangerousArguments: []int{0}, Priority: 0.9, Evidence: "inferred",
			Limitations: []string{"presence is not exploitability"},
		}},
	}
	cases := map[string]func(*javaSinkCatalog){
		"duplicate": func(c *javaSinkCatalog) {
			c.Entries = append(c.Entries, c.Entries[0])
		},
		"exact without receiver": func(c *javaSinkCatalog) {
			c.Entries[0].Match.ReceiverType = ""
		},
		"unknown match mode": func(c *javaSinkCatalog) {
			c.Entries[0].Match.MatchType = "somehow"
		},
		"argument overflow": func(c *javaSinkCatalog) {
			c.Entries[0].DangerousArguments = []int{64}
		},
		"priority overflow": func(c *javaSinkCatalog) {
			c.Entries[0].Priority = 1.1
		},
		"missing limitation": func(c *javaSinkCatalog) {
			c.Entries[0].Limitations = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			catalog := base
			catalog.Entries = append([]javaSinkEntry(nil), base.Entries...)
			mutate(&catalog)
			if err := validateJavaCatalog(catalog); err == nil {
				t.Fatal("invalid catalog was accepted")
			}
		})
	}
}

func TestJavaSinkCatalogDigestIgnoresFileFormatting(t *testing.T) {
	dir := t.TempDir()
	catalog := `{"api_version":"codexploit/java-sink-catalog/v1","id":"java-sink-catalog","version":"1.0.0","entries":[{"id":"java.test.sink","category":"deserialization","match":{"receiver_type":"java.io.ObjectInputStream","method":"readObject","match_type":"exact"},"dangerous_arguments":[0],"priority":0.9,"evidence":"inferred","limitations":["presence is not exploitability"]}]}`
	if err := os.WriteFile(filepath.Join(dir, "java-sinks.json"), []byte(catalog), 0600); err != nil {
		t.Fatal(err)
	}
	_, first, err := loadJavaCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	pretty := strings.ReplaceAll(catalog, ",", ",\n  ")
	if err := os.WriteFile(filepath.Join(dir, "java-sinks.json"), []byte(pretty), 0600); err != nil {
		t.Fatal(err)
	}
	_, second, err := loadJavaCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("formatting changed canonical digest: %s != %s", first, second)
	}
}
