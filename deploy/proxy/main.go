// Stock Caddy, no third-party plugins. Built by deploy/Dockerfile.proxy with -mod=readonly against the
// committed go.mod/go.sum, so the module versions and hashes below are the reviewed ones.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() { caddycmd.Main() }
