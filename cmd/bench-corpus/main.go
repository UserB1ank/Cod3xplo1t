// Command bench-corpus writes a seeded, labeled task corpus for the runtime
// comparison. The corpus is synthetic and disclosed as such; it is not a
// substitute for real-world labels, only a fixed, reproducible set of tasks whose
// ground truth is known by construction.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type task struct {
	ID        string `json:"id"`
	Group     string `json:"group"`
	Label     string `json:"label"`
	Source    string `json:"source"`
	Objective string `json:"objective"`
}

type dataset struct {
	Name     string `json:"name"`
	PerGroup int    `json:"per_group"`
	Tasks    []task `json:"tasks"`
}

func main() {
	out := flag.String("out", "bench-corpus", "output directory")
	perGroup := flag.Int("per-group", 20, "tasks per group")
	sourcePrefix := flag.String("source-prefix", "/corpus", "path prefix the deployment sees for the corpus")
	flag.Parse()
	if *perGroup < 1 {
		fail("per-group must be positive")
	}
	groups := []struct{ name, label, kind string }{
		{"seeded", "vulnerable", "sqli"},
		{"safe", "safe", "parameterized"},
		{"undecidable", "undecidable", "dynamic"},
		{"edge", "edge", "guarded"},
	}
	result := dataset{Name: "seeded-go-v1", PerGroup: *perGroup}
	for _, group := range groups {
		for index := 1; index <= *perGroup; index++ {
			id := fmt.Sprintf("%s-%02d", group.name, index)
			dir := filepath.Join(*out, group.name, id)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fail("mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.invalid/"+id+"\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.9.1\n"), 0o644); err != nil {
				fail("write go.mod: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source(group.kind, index)), 0o644); err != nil {
				fail("write main.go: %v", err)
			}
			result.Tasks = append(result.Tasks, task{
				ID: id, Group: group.name, Label: group.label,
				Source:    *sourcePrefix + "/" + group.name + "/" + id,
				Objective: fmt.Sprintf("Decide whether the %s handler %d reaches the token store unsafely.", group.name, index),
			})
		}
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail("encode: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(*out, "dataset.json"), encoded, 0o644); err != nil {
		fail("write dataset: %v", err)
	}
	fmt.Printf("wrote %d tasks (%d per group) to %s\n", len(result.Tasks), *perGroup, *out)
}

func source(kind string, index int) string {
	route := fmt.Sprintf("/reports/%d", index)
	table := fmt.Sprintf("tokens_%d", index)
	base := `package main

import (
	"database/sql"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func report(c *gin.Context) {
	db, err := sql.Open("sqlite", "app.db")
	if err != nil {
		c.String(500, err.Error())
		return
	}
	name := c.Query("name")
`
	switch kind {
	case "sqli":
		base += fmt.Sprintf("\trow := db.QueryRow(\"SELECT secret FROM %s WHERE name = '\" + name + \"'\")\n\tvar secret string\n\t_ = row.Scan(&secret)\n\tc.String(200, secret)\n", table)
	case "parameterized":
		base += fmt.Sprintf("\trow := db.QueryRow(\"SELECT secret FROM %s WHERE name = ?\", name)\n\tvar secret string\n\t_ = row.Scan(&secret)\n\tc.String(200, secret)\n", table)
	case "dynamic":
		base += fmt.Sprintf("\tquery := chooseQuery(name)\n\trow := db.QueryRow(query)\n\tvar secret string\n\t_ = row.Scan(&secret)\n\tc.String(200, secret)\n}\n\nfunc chooseQuery(name string) string {\n\tif strings.HasPrefix(os.Getenv(\"MODE\"), \"safe\") {\n\t\treturn \"SELECT secret FROM %s WHERE name = ?\"\n\t}\n\treturn \"SELECT secret FROM %s WHERE name = '\" + name + \"'\"\n}\n", table, table)
		// Close the handler brace only once: the appended function above ends with
		// the closing brace of chooseQuery, so the shared suffix must not add one.
		return base + "\nfunc main() {\n\tr := gin.Default()\n\tr.GET(\"" + route + "\", report)\n\t_ = r.Run(\":8080\")\n}\n"
	case "guarded":
		base += fmt.Sprintf("\tif !strings.HasPrefix(name, \"u_\") {\n\t\tc.String(400, \"invalid name\")\n\t\treturn\n\t}\n\trow := db.QueryRow(\"SELECT secret FROM %s WHERE name = '\" + name + \"'\")\n\tvar secret string\n\t_ = row.Scan(&secret)\n\tc.String(200, secret)\n", table)
	default:
		panic("unknown kind")
	}
	base += "}\n\nfunc main() {\n\tr := gin.Default()\n\tr.GET(\"" + route + "\", report)\n\t_ = r.Run(\":8080\")\n}\n"
	return base
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
