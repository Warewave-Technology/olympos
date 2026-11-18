// Command olympos-server is the central Olympos server.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Warewave-Technology/olympos/internal/app"
)

func main() {
	cfg := flag.String("config", os.Getenv("OLYMPOS_CONFIG"), "path to config file (YAML)")
	flag.Parse()
	if err := app.Run(*cfg); err != nil {
		fmt.Fprintln(os.Stderr, "olympos-server:", err)
		os.Exit(1)
	}
}
