//go:build js && wasm

// Command wasm exposes the core operations to JavaScript as
// threatCore.call(op, requestJSON) -> responseJSON. The web app runs it in a
// Web Worker; see web/src/core.
package main

import (
	"syscall/js"

	"github.com/open-security-tooling/threat-model/internal/ops"
)

func main() {
	call := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return `{"error":{"message":"call(op, requestJSON) takes two arguments"}}`
		}
		return string(ops.Call(args[0].String(), []byte(args[1].String())))
	})
	js.Global().Set("threatCore", js.ValueOf(map[string]any{
		"call":    call,
		"ops":     js.ValueOf(toAny(ops.Names)),
		"version": "0.1.0-dev",
	}))
	select {}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
