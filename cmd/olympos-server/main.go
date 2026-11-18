// Command olympos-server is the central Olympos server.
//
//	olympos-server [-config FILE]               run the server
//	olympos-server migrate [-config FILE]       apply migrations and exit
//	olympos-server check-config [-config FILE] [-db]
//	olympos-server version
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/Warewave-Technology/olympos/internal/app"
	"github.com/Warewave-Technology/olympos/internal/devbuild"
	"github.com/Warewave-Technology/olympos/internal/version"
)

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("olympos-server "+cmd, flag.ExitOnError)
	cfg := fs.String("config", defaultConfig(), "path to config file (YAML)")
	db := fs.Bool("db", false, "check-config: also connect to the database")
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "serve":
		err = app.Run(*cfg)
	case "migrate":
		err = app.Migrate(*cfg)
	case "check-config":
		err = app.CheckConfig(*cfg, *db)
	case "version":
		build := "release"
		if devbuild.Enabled {
			build = "dev"
		}
		fmt.Printf("olympos-server %s (%s build, %s, %s/%s)\n", version.Version, build, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, "olympos-server: unknown command %q (serve, migrate, check-config, version)\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "olympos-server:", err)
		os.Exit(1)
	}
}

// defaultConfig: OLYMPOS_CONFIG, else /etc/olympos/config.yaml when present
// (packages install it there).
func defaultConfig() string {
	if v := os.Getenv("OLYMPOS_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat("/etc/olympos/config.yaml"); err == nil {
		return "/etc/olympos/config.yaml"
	}
	return ""
}
