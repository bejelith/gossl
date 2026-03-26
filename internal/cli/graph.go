package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bejelith/gossl/internal/store"
	"github.com/spf13/cobra"
)

func newGraphCmd() *cobra.Command {
	var (
		db     string
		out    string
		filter string
		format string
	)

	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Generate a diagram of the CA hierarchy",
		Long: `Render all CAs and certificates as a tree diagram from a gossl database.
Use --filter to include only specific node types (comma-separated: ca, intermediate, cert).
Use --format to choose output format: svg, json, or text.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				ext := map[string]string{"svg": ".svg", "json": ".json", "text": ".txt"}[format]
				out = strings.TrimSuffix(db, filepath.Ext(db)) + ext
			}
			return runGraph(cmd.Context(), db, out, filter, format)
		},
	}

	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&out, "out", "", "Output file path (defaults to <db>.<format>)")
	cmd.Flags().StringVar(&filter, "filter", "", "Node types to include (comma-separated: ca, intermediate, cert)")
	cmd.Flags().StringVar(&format, "format", "svg", "Output format: svg, json, text")

	return cmd
}

func parseFilter(filter string) map[string]bool {
	if filter == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, f := range strings.Split(filter, ",") {
		m[strings.TrimSpace(f)] = true
	}
	return m
}

func runGraph(ctx context.Context, dbPath, out, filter, format string) error {
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	show := parseFilter(filter)

	var cas []store.Ca
	if show == nil || show["ca"] || show["intermediate"] {
		cas, err = q.ListCAs(ctx)
		if err != nil {
			return fmt.Errorf("listing CAs: %w", err)
		}
		if show != nil {
			var filtered []store.Ca
			for _, ca := range cas {
				if !ca.ParentID.Valid && show["ca"] {
					filtered = append(filtered, ca)
				} else if ca.ParentID.Valid && show["intermediate"] {
					filtered = append(filtered, ca)
				}
			}
			// Always include ancestors of visible nodes so the tree connects
			cas = includeAncestors(filtered, cas)
		}
	}

	var certs []store.Cert
	if show == nil || show["cert"] {
		certs, err = q.ListCerts(ctx)
		if err != nil {
			return fmt.Errorf("listing certs: %w", err)
		}
	}

	var content string
	switch format {
	case "svg":
		content = renderSVG(cas, certs)
	case "json":
		content = renderJSON(cas, certs)
	case "text":
		content = renderText(cas, certs)
	default:
		return fmt.Errorf("unsupported format %q (use svg, json, or text)", format)
	}

	if err := os.WriteFile(out, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Graph written to %s (%d CAs, %d certs)\n", out, len(cas), len(certs))
	return nil
}

type node struct {
	id       string
	label    string
	kind     string // "root", "intermediate", "cert", "revoked"
	children []*node
}

// includeAncestors ensures parent CAs of visible nodes are included so the tree is connected.
func includeAncestors(visible, all []store.Ca) []store.Ca {
	byID := make(map[int64]store.Ca)
	for _, ca := range all {
		byID[ca.ID] = ca
	}

	included := make(map[int64]bool)
	for _, ca := range visible {
		included[ca.ID] = true
	}

	// Walk up from each visible node
	for _, ca := range visible {
		cur := ca
		for cur.ParentID.Valid {
			if included[cur.ParentID.Int64] {
				break
			}
			included[cur.ParentID.Int64] = true
			cur = byID[cur.ParentID.Int64]
		}
	}

	var result []store.Ca
	for _, ca := range all {
		if included[ca.ID] {
			result = append(result, ca)
		}
	}
	return result
}

// --- JSON format ---

type jsonNode struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Serial   string      `json:"serial"`
	Children []*jsonNode `json:"children,omitempty"`
}

func renderJSON(cas []store.Ca, certs []store.Cert) string {
	caByID := make(map[int64]*jsonNode)
	var roots []*jsonNode

	for _, ca := range cas {
		kind := "intermediate"
		if !ca.ParentID.Valid {
			kind = "root"
		}
		n := &jsonNode{Name: ca.CommonName, Type: kind, Serial: ca.Serial}
		caByID[ca.ID] = n
	}

	for _, ca := range cas {
		n := caByID[ca.ID]
		if ca.ParentID.Valid {
			if parent, ok := caByID[ca.ParentID.Int64]; ok {
				parent.Children = append(parent.Children, n)
			}
		} else {
			roots = append(roots, n)
		}
	}

	for _, cert := range certs {
		kind := "cert"
		if cert.RevokedAt.Valid {
			kind = "revoked"
		}
		n := &jsonNode{Name: cert.CommonName, Type: kind, Serial: cert.Serial}
		if parent, ok := caByID[cert.CaID]; ok {
			parent.Children = append(parent.Children, n)
		}
	}

	data, _ := json.MarshalIndent(roots, "", "  ")
	return string(data) + "\n"
}

// --- Text format ---

func renderText(cas []store.Ca, certs []store.Cert) string {
	caByID := make(map[int64]*node)
	var roots []*node

	for _, ca := range cas {
		kind := "intermediate"
		if !ca.ParentID.Valid {
			kind = "root"
		}
		n := &node{id: ca.Serial, label: ca.CommonName, kind: kind}
		caByID[ca.ID] = n
	}

	for _, ca := range cas {
		n := caByID[ca.ID]
		if ca.ParentID.Valid {
			if parent, ok := caByID[ca.ParentID.Int64]; ok {
				parent.children = append(parent.children, n)
			}
		} else {
			roots = append(roots, n)
		}
	}

	for _, cert := range certs {
		kind := "cert"
		if cert.RevokedAt.Valid {
			kind = "revoked"
		}
		n := &node{id: cert.Serial, label: cert.CommonName, kind: kind}
		if parent, ok := caByID[cert.CaID]; ok {
			parent.children = append(parent.children, n)
		}
	}

	var b strings.Builder
	for _, root := range roots {
		printTreeRoot(&b, root)
	}
	return b.String()
}

func printTreeRoot(b *strings.Builder, n *node) {
	tag := nodeTag(n.kind)
	b.WriteString(fmt.Sprintf("%s%s\n", n.label, tag))
	for i, child := range n.children {
		printTreeNode(b, child, "", i == len(n.children)-1)
	}
}

func printTreeNode(b *strings.Builder, n *node, prefix string, last bool) {
	connector := "├── "
	childExt := "│   "
	if last {
		connector = "└── "
		childExt = "    "
	}

	tag := nodeTag(n.kind)
	b.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, connector, n.label, tag))

	childPrefix := prefix + childExt
	for i, child := range n.children {
		printTreeNode(b, child, childPrefix, i == len(n.children)-1)
	}
}

func nodeTag(kind string) string {
	switch kind {
	case "root":
		return " [ROOT]"
	case "revoked":
		return " [REVOKED]"
	default:
		return ""
	}
}

// --- SVG format ---

func renderSVG(cas []store.Ca, certs []store.Cert) string {
	// Build tree
	caByID := make(map[int64]*node)
	var roots []*node

	for _, ca := range cas {
		kind := "intermediate"
		if !ca.ParentID.Valid {
			kind = "root"
		}
		n := &node{
			id:    fmt.Sprintf("ca_%d", ca.ID),
			label: ca.CommonName,
			kind:  kind,
		}
		caByID[ca.ID] = n
	}

	// Link parents
	for _, ca := range cas {
		n := caByID[ca.ID]
		if ca.ParentID.Valid {
			if parent, ok := caByID[ca.ParentID.Int64]; ok {
				parent.children = append(parent.children, n)
			}
		} else {
			roots = append(roots, n)
		}
	}

	// Attach certs to their CA
	for _, cert := range certs {
		kind := "cert"
		if cert.RevokedAt.Valid {
			kind = "revoked"
		}
		n := &node{
			id:    fmt.Sprintf("cert_%d", cert.ID),
			label: cert.CommonName,
			kind:  kind,
		}
		if parent, ok := caByID[cert.CaID]; ok {
			parent.children = append(parent.children, n)
		}
	}

	// Layout: compute positions with DFS
	type pos struct {
		x, y float64
		n    *node
	}

	var positions []pos
	type edge struct {
		x1, y1, x2, y2 float64
	}
	var edges []edge

	const (
		nodeW    = 220.0
		nodeH    = 36.0
		padX     = 40.0
		padY     = 60.0
		marginX  = 30.0
		marginY  = 30.0
	)

	curX := marginX
	var layoutNode func(n *node, depth int)
	layoutNode = func(n *node, depth int) {
		y := marginY + float64(depth)*(nodeH+padY)
		x := curX
		positions = append(positions, pos{x: x, y: y, n: n})
		myIdx := len(positions) - 1

		if len(n.children) == 0 {
			curX += nodeW + padX
			return
		}

		childStartX := curX
		for _, child := range n.children {
			layoutNode(child, depth+1)
		}
		childEndX := curX - padX

		// Center parent over children
		centerX := (childStartX + childEndX + nodeW) / 2.0 - nodeW/2.0
		positions[myIdx] = pos{x: centerX, y: y, n: n}

		// Add edges
		px := centerX + nodeW/2.0
		py := y + nodeH
		for _, child := range n.children {
			for _, p := range positions {
				if p.n == child {
					cx := p.x + nodeW/2.0
					cy := p.y
					edges = append(edges, edge{px, py, cx, cy})
					break
				}
			}
		}
	}

	for _, root := range roots {
		layoutNode(root, 0)
	}

	// Compute SVG dimensions
	maxX := marginX
	maxY := marginY
	for _, p := range positions {
		if p.x+nodeW > maxX {
			maxX = p.x + nodeW
		}
		if p.y+nodeH > maxY {
			maxY = p.y + nodeH
		}
	}
	svgW := maxX + marginX
	svgH := maxY + marginY

	// Render SVG
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f">`, svgW, svgH, svgW, svgH))
	b.WriteString("\n<style>\n")
	b.WriteString("  .root rect { fill: #2563eb; stroke: #1e40af; }\n")
	b.WriteString("  .intermediate rect { fill: #7c3aed; stroke: #5b21b6; }\n")
	b.WriteString("  .cert rect { fill: #059669; stroke: #047857; }\n")
	b.WriteString("  .revoked rect { fill: #dc2626; stroke: #b91c1c; }\n")
	b.WriteString("  rect { rx: 6; ry: 6; stroke-width: 2; }\n")
	b.WriteString("  text { fill: white; font-family: sans-serif; font-size: 12px; text-anchor: middle; dominant-baseline: central; }\n")
	b.WriteString("  line { stroke: #94a3b8; stroke-width: 2; }\n")
	b.WriteString("</style>\n")

	// Draw edges
	for _, e := range edges {
		b.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`, e.x1, e.y1, e.x2, e.y2))
		b.WriteString("\n")
	}

	// Draw nodes
	for _, p := range positions {
		label := p.n.label
		if len(label) > 28 {
			label = label[:25] + "..."
		}
		b.WriteString(fmt.Sprintf(`<g class="%s"><rect x="%.1f" y="%.1f" width="%.0f" height="%.0f"/><text x="%.1f" y="%.1f">%s</text></g>`,
			p.n.kind, p.x, p.y, nodeW, nodeH,
			p.x+nodeW/2, p.y+nodeH/2,
			escapeXML(label)))
		b.WriteString("\n")
	}

	b.WriteString("</svg>\n")
	return b.String()
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
