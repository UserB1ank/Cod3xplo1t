package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCPGLanguagesUsesPublishedCanonicalFileReferences(t *testing.T) {
	var code codeData
	if err := json.Unmarshal([]byte(`{
		"files": [
			{"file_id":"scg:file-java","path":"src/Main.java","language":"Java","parse_status":"parsed"},
			{"file_id":"scg:file-kotlin","path":"src/Main.kt","language":"Kotlin","parse_status":"parsed"}
		],
		"native_id_mappings": [
			{"native_artifact_ref":"cpg-java","native_id":"1","canonical_ref":"scg:file-java"},
			{"native_artifact_ref":"cpg-kotlin","native_id":"2","canonical_ref":"scg:file-kotlin"}
		]
	}`), &code); err != nil {
		t.Fatal(err)
	}
	got := cpgLanguages(code)
	want := map[string][]string{
		"cpg-java":   {"Java"},
		"cpg-kotlin": {"Kotlin"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CPG languages = %#v, want %#v", got, want)
	}
}
