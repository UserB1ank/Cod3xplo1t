package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

const javaCatalogAPIVersion = "codexploit/java-sink-catalog/v1"

type javaSinkCatalog struct {
	APIVersion string          `json:"api_version"`
	ID         string          `json:"id"`
	Version    string          `json:"version"`
	Entries    []javaSinkEntry `json:"entries"`
}

type javaSinkEntry struct {
	ID                 string        `json:"id"`
	Category           string        `json:"category"`
	Match              javaSinkMatch `json:"match"`
	DangerousArguments []int         `json:"dangerous_arguments"`
	Priority           float64       `json:"priority"`
	Evidence           string        `json:"evidence"`
	Limitations        []string      `json:"limitations"`
}

type javaSinkMatch struct {
	ReceiverType string `json:"receiver_type"`
	Method       string `json:"method"`
	MatchType    string `json:"match_type"`
}

type catalogRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Entries int    `json:"entries"`
}

// loadJavaCatalog validates the package-owned catalogue and hashes its canonical
// decoded form. Re-formatting the JSON therefore cannot change analysis identity,
// while any semantic change does.
func loadJavaCatalog(packageRoot string) (*javaSinkCatalog, string, error) {
	raw, err := os.ReadFile(filepath.Join(packageRoot, "java-sinks.json"))
	if err != nil {
		return nil, "", failed("dependency_unavailable")
	}
	var catalog javaSinkCatalog
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return nil, "", failed("invalid_catalog")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, "", failed("invalid_catalog")
	}
	if err := validateJavaCatalog(catalog); err != nil {
		return nil, "", failed("invalid_catalog")
	}
	canonical, err := json.Marshal(catalog)
	if err != nil {
		return nil, "", failed("invalid_catalog")
	}
	return &catalog, digest(canonical), nil
}

func validateJavaCatalog(catalog javaSinkCatalog) error {
	if catalog.APIVersion != javaCatalogAPIVersion || catalog.ID != "java-sink-catalog" || catalog.Version == "" || len(catalog.Entries) == 0 || len(catalog.Entries) > 256 {
		return fmt.Errorf("invalid Java sink catalogue identity")
	}
	categories := map[string]bool{
		asg.SinkProcess: true, asg.SinkDeserialization: true, asg.SinkExpressionInjection: true,
		asg.SinkJNDI: true, asg.SinkSQL: true, asg.SinkXXE: true, asg.SinkNetwork: true,
		asg.SinkFileRead: true, asg.SinkFileWrite: true, asg.SinkLDAP: true,
		asg.SinkTemplateInjection: true,
	}
	seen := map[string]bool{}
	for _, entry := range catalog.Entries {
		if entry.ID == "" || seen[entry.ID] || len(entry.ID) > 128 || !categories[entry.Category] {
			return fmt.Errorf("invalid or duplicate Java sink entry %q", entry.ID)
		}
		seen[entry.ID] = true
		if entry.Match.MatchType != "exact" && entry.Match.MatchType != "regex" {
			return fmt.Errorf("invalid match type for %s", entry.ID)
		}
		if entry.Match.Method == "" || len(entry.Match.Method) > 512 || len(entry.Match.ReceiverType) > 512 {
			return fmt.Errorf("invalid match for %s", entry.ID)
		}
		if entry.Match.MatchType == "exact" && entry.Match.ReceiverType == "" {
			return fmt.Errorf("exact entry %s has no receiver type", entry.ID)
		}
		if entry.Match.MatchType == "regex" {
			if _, err := regexp.Compile(entry.Match.Method); err != nil {
				return fmt.Errorf("invalid method regex for %s", entry.ID)
			}
			if entry.Match.ReceiverType != "" {
				if _, err := regexp.Compile(entry.Match.ReceiverType); err != nil {
					return fmt.Errorf("invalid receiver regex for %s", entry.ID)
				}
			}
		}
		args := map[int]bool{}
		for _, argument := range entry.DangerousArguments {
			if argument < 0 || argument > 63 || args[argument] {
				return fmt.Errorf("invalid dangerous argument for %s", entry.ID)
			}
			args[argument] = true
		}
		if entry.Priority < 0 || entry.Priority > 1 || (entry.Evidence != "observed" && entry.Evidence != "inferred") || len(entry.Limitations) == 0 {
			return fmt.Errorf("invalid evidence policy for %s", entry.ID)
		}
	}
	return nil
}
