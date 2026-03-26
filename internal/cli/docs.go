package cli

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed userdocs/*.md
var docsFS embed.FS

func newDocsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docs [topic]",
		Short: "Print built-in documentation (useful for LLM context)",
		Long: `Dump embedded user documentation to stdout. Without arguments, prints all docs.
With a topic, prints only that section.

Topics: getting-started, ca-management, certificates, keys, csr, sclient, serve, troubleshooting

Designed to be piped into an LLM prompt for context:
  gossl docs | llm "how do I set up mTLS with gossl?"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			topic := ""
			if len(args) > 0 {
				topic = args[0]
			}
			return runDocs(topic)
		},
	}

	return cmd
}

func runDocs(topic string) error {
	entries, err := fs.ReadDir(docsFS, "userdocs")
	if err != nil {
		return fmt.Errorf("reading embedded docs: %w", err)
	}

	// Filter to .md files only
	var mdFiles []fs.DirEntry
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".md") {
			mdFiles = append(mdFiles, e)
		}
	}

	sort.Slice(mdFiles, func(i, j int) bool {
		return mdFiles[i].Name() < mdFiles[j].Name()
	})

	if topic != "" {
		target := topic + ".md"
		for _, e := range mdFiles {
			if e.Name() == target {
				return printDoc(e.Name())
			}
		}
		for _, e := range mdFiles {
			if strings.Contains(e.Name(), topic) {
				return printDoc(e.Name())
			}
		}
		return fmt.Errorf("unknown topic %q. Available: %s", topic, listTopics(mdFiles))
	}

	fmt.Println("# gossl Documentation")
	fmt.Println()
	fmt.Println("The following is the complete documentation for gossl, a simplified")
	fmt.Println("alternative to openssl for mTLS certificate management and troubleshooting.")
	fmt.Println()

	for _, e := range mdFiles {
		if err := printDoc(e.Name()); err != nil {
			return err
		}
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}

	return nil
}

func printDoc(name string) error {
	data, err := docsFS.ReadFile("userdocs/" + name)
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	fmt.Print(string(data))
	return nil
}

func listTopics(entries []fs.DirEntry) string {
	var topics []string
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".md")
		topics = append(topics, name)
	}
	return strings.Join(topics, ", ")
}
