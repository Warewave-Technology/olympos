// Command olympos-sh is installed as /bin/sh in the distroless server image.
// It is NOT a shell: libpq tools (pg_dumpall locating pg_dump via popen)
// call `/bin/sh -c '"<path>" -V'`, and distroless has no shell. This shim
// accepts exactly `-c <command>` where command is one program with plainly
// quoted arguments, refuses every shell metacharacter, and execs it.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "-c" {
		fail("only `-c <command>` is supported")
	}
	argv, err := split(os.Args[2])
	if err != nil {
		fail(err.Error())
	}
	if len(argv) == 0 || !strings.HasPrefix(argv[0], "/") {
		fail("command must be an absolute path")
	}
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "olympos-sh:", msg)
	os.Exit(127)
}

// split tokenizes words with single/double quotes. Any character with shell
// meaning outside quotes ( | & ; < > ( ) $ ` \ * ? [ ] { } ~ # newline) is
// rejected, as is $ ` \ inside double quotes.
func split(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("unterminated quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				return nil, fmt.Errorf("unterminated quote")
			}
			part := s[i+1 : i+1+j]
			if strings.ContainsAny(part, "$`\\") {
				return nil, fmt.Errorf("expansion is not supported")
			}
			cur.WriteString(part)
			i += j + 1
			inWord = true
		case strings.IndexByte("|&;<>()$`\\*?[]{}~#\n\r", c) >= 0:
			return nil, fmt.Errorf("shell syntax is not supported")
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out, nil
}
