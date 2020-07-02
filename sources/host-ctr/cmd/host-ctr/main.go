package main

import (
	"os"

	"host_ctr"
)

func main() {
	os.Exit(host_ctr.Main(os.Args[1:]))
}
