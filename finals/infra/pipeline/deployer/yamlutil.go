package main

// minimal YAML parser for gate.yml only - handles simple key: value and list items.
// not a general parser.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func parseGateYML(path string) (*gateYML, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	g := &gateYML{}
	var curList *[]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// list item
		if strings.HasPrefix(trimmed, "- ") {
			if curList != nil {
				*curList = append(*curList, strings.TrimPrefix(trimmed, "- "))
			}
			continue
		}

		// key: value
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		// strip inline comment (# outside quotes)
		if ci := strings.Index(v, " #"); ci >= 0 {
			v = v[:ci]
		}
		v = strings.TrimSpace(v)

		switch k {
		case "service":
			g.Service = v
			curList = nil
		case "port":
			g.Port, _ = strconv.Atoi(v)
			curList = nil
		case "flag_stores":
			g.FlagStores, _ = strconv.Atoi(v)
			curList = nil
		case "patchable":
			curList = &g.Patchable
		case "secrets":
			curList = &g.Secrets
		default:
			curList = nil
		}
	}
	return g, sc.Err()
}
