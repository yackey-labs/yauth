package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	yauth "github.com/yackey-labs/yauth"
)

// docTopic is one embedded markdown document, addressable by a stable slug.
type docTopic struct {
	Slug  string `json:"slug"`
	Title string `json:"title"`
	Path  string `json:"path"`
}

// docTopics walks the embedded docs tree and returns every markdown file as a
// topic. Slugs are derived from the path so they are stable and predictable
// for an agent: README.md -> "readme", docs/scim/okta.md -> "scim/okta",
// docs/scim/README.md -> "scim".
func docTopics() ([]docTopic, error) {
	var topics []docTopic
	err := fs.WalkDir(yauth.DocsFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		topics = append(topics, docTopic{Slug: slugFor(p), Title: titleOf(p), Path: p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(topics, func(i, j int) bool { return topics[i].Slug < topics[j].Slug })
	return topics, nil
}

func slugFor(p string) string {
	s := strings.TrimSuffix(p, ".md")
	s = strings.TrimPrefix(s, "docs/")
	if s == "README" {
		return "readme"
	}
	s = strings.TrimSuffix(s, "/README")
	return strings.ToLower(s)
}

// titleOf returns the first markdown H1 in the file, falling back to the slug.
func titleOf(p string) string {
	f, err := yauth.DocsFS.Open(p)
	if err != nil {
		return slugFor(p)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return slugFor(p)
}

func newDocsCmd() *cobra.Command {
	var asJSON, full bool
	cmd := &cobra.Command{
		Use:   "docs [topic]",
		Short: "Print embedded, version-exact docs (no args lists topics)",
		Long: "Print documentation embedded in this binary. With no topic it lists " +
			"available topics; with a topic it prints that document; --full prints " +
			"every document concatenated.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			topics, err := docTopics()
			if err != nil {
				return err
			}

			if full {
				for i, t := range topics {
					if i > 0 {
						fmt.Fprintf(out, "\n\n---\n\n")
					}
					b, err := fs.ReadFile(yauth.DocsFS, t.Path)
					if err != nil {
						return err
					}
					out.Write(b)
				}
				return nil
			}

			if len(args) == 0 {
				if asJSON {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(topics)
				}
				fmt.Fprintln(out, "# yauth docs — available topics")
				fmt.Fprintln(out)
				fmt.Fprintln(out, "Run `yauth docs <topic>`, or `yauth docs --full` for everything.")
				fmt.Fprintln(out)
				for _, t := range topics {
					fmt.Fprintf(out, "- %s — %s\n", t.Slug, t.Title)
				}
				return nil
			}

			want := strings.ToLower(args[0])
			for _, t := range topics {
				if t.Slug == want {
					b, err := fs.ReadFile(yauth.DocsFS, t.Path)
					if err != nil {
						return err
					}
					out.Write(b)
					return nil
				}
			}
			return fmt.Errorf("unknown docs topic %q; run `yauth docs` to list topics", args[0])
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "list topics as JSON")
	cmd.Flags().BoolVar(&full, "full", false, "print every document concatenated")
	return cmd
}
