package main

import (
	"os"
	"context"

	"host_ctr"
)

func main() {
	// Configure the logger.
	host_ctr.UseLogSplitHook()

	os.Exit(host_ctr.Main(context.Background(), os.Args[1:]))
}
