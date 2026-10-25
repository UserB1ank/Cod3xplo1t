package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type frontend struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Module     string   `json:"module"`
	MainClass  string   `json:"main_class"`
	Extensions []string `json:"extensions"`
	Kind       string   `json:"kind"`
	Arguments  []string `json:"arguments"`
}

func loadFrontends(root string) ([]frontend, error) {
	raw, err := os.ReadFile(filepath.Join(root, "frontends.json"))
	if err != nil {
		return nil, err
	}
	var catalog struct {
		Frontends []frontend `json:"frontends"`
	}
	err = json.Unmarshal(raw, &catalog)
	return catalog.Frontends, err
}
func (f frontend) matches(path string) bool {
	for _, ext := range f.Extensions {
		if strings.EqualFold(filepath.Ext(path), ext) {
			return true
		}
	}
	return false
}
func (f frontend) language(path string) string {
	if f.ID == "C" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx":
			return "C++"
		}
		return "C"
	}
	if f.ID == "JAVASCRIPT" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".ts", ".tsx":
			return "TypeScript"
		}
		return "JavaScript"
	}
	return f.Name
}
func selectFrontends(all []frontend, requested string, files map[string]bool) ([]frontend, error) {
	requested = strings.ToUpper(requested)
	if requested == "" {
		requested = "AUTO"
	}
	aliases := map[string]string{"NEWC": "C", "JSSRC": "JAVASCRIPT", "PYTHON": "PYTHONSRC"}
	if id := aliases[requested]; id != "" {
		requested = id
	}
	selected := []frontend{}
	for _, f := range all {
		if requested == f.ID {
			return []frontend{f}, nil
		}
		if requested == "AUTO" && f.Kind != "binary" {
			for path := range files {
				if f.matches(path) {
					selected = append(selected, f)
					break
				}
			}
		}
	}
	if len(selected) == 0 {
		return nil, os.ErrNotExist
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	return selected, nil
}
