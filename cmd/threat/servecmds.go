package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/open-security-tooling/threat-model/internal/mcp"
	"github.com/open-security-tooling/threat-model/internal/serve"
	"github.com/open-security-tooling/threat-model/internal/webassets"
)

func cmdServe(args []string) int {
	f := newFlags("serve", "serve [--file threatmodel.yaml] [--addr 127.0.0.1:0] [--no-open]")
	addr := f.String("addr", "127.0.0.1:0", "address to listen on (loopback only)")
	noOpen := f.Bool("no-open", false, "don't open a browser")
	if !f.parse(args) {
		return exitUsage
	}
	path, err := f.modelPath()
	if err != nil {
		fail(err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = serve.Run(ctx, serve.Options{
		File:   path,
		Addr:   *addr,
		Assets: webassets.FS(),
		OnReady: func(url string) {
			fmt.Printf("Serving %s at %s\nThe link contains a secret token for this run; don't share it. Press Ctrl+C to stop.\n", path, url)
			if !*noOpen {
				openBrowser(url)
			}
		},
	})
	if err != nil {
		fail(err)
		return exitUsage
	}
	return exitOK
}

// openBrowser opens url without a shell, so nothing in it is interpreted.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func cmdMCP(args []string) int {
	f := newFlags("mcp", "mcp [--file threatmodel.yaml] [--allow-accept] [--allow-risk-lowering] [--read-only]")
	allowAccept := f.Bool("allow-accept", false, "let the agent accept risks (off by default: accepting risk is a human decision)")
	allowLowering := f.Bool("allow-risk-lowering", false, "let the agent delete threats, mark high or critical threats not-applicable, lower who/effort/impact, set risk overrides and record component reviews (off by default: a person should make those changes)")
	readOnly := f.Bool("read-only", false, "refuse every change; the agent can only read, check and explain")
	if !f.parse(args) {
		return exitUsage
	}
	path, err := f.modelPath()
	if err != nil {
		fail(err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := mcp.Run(ctx, mcp.Options{File: path, AllowAccept: *allowAccept, AllowRiskLowering: *allowLowering, ReadOnly: *readOnly, Version: version}, os.Stdin, os.Stdout); err != nil {
		fail(err)
		return exitUsage
	}
	return exitOK
}
