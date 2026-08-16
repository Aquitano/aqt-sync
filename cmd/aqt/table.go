// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// printTable writes rows to out as a column-aligned table, one line per row. A nil
// header prints no header line, which is how the key/value summaries render. Every
// cell is already a string, so a column's width is exactly what it prints.
func printTable(out io.Writer, header []string, rows [][]string) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if header != nil {
		fmt.Fprintln(w, strings.Join(header, "\t"))
	}
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	return w.Flush()
}
