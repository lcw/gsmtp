package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"runtime"
)

// This gets gets the home directory in a way that can be cross compiled.  This
// approach was taken from:
//
//   https://stackoverflow.com/questions/7922270/obtain-users-home-directory
func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

var defaultConfigFile = path.Join(userHomeDir(), "config", "gsmtp", "init.toml")

var configFile = flag.String("config", defaultConfigFile,
	"File to read configuration from")
var dumpConfigFlag = flag.Bool("dump-config", false, "Read and print configfile")

func main() {
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: unused arguments %v\n", flag.Args())
	}

	println("Reading config file:", *configFile)
	println("Dump Config:", *dumpConfigFlag)

	os.Exit(1)
}
