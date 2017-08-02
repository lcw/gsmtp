package main

import (
	"flag"
	"fmt"
	"os"
)

var dumpConfigFlag = flag.Bool("dump-config", false, "Read and print configfile")

func main() {
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: unused arguments %v\n", flag.Args())
	}

	println("Dump Config:", *dumpConfigFlag)

	os.Exit(1)
}
