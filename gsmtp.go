package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/BurntSushi/toml"
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

var defaultConfigFile = path.Join(userHomeDir(), ".config", "gsmtp", "init.toml")

var configFile = flag.String("config", defaultConfigFile,
	"File to read configuration from")
var dumpConfigFlag = flag.Bool("dump-config", false, "Read and print configfile")

type server struct {
	Addr string `toml:"address,omitempty"`
}
type servers map[string]server

func main() {
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: unused arguments %v\n", flag.Args())
	}

	println("Flags:")
	println("  Reading config file:", *configFile)
	println("  Dump Config:", *dumpConfigFlag)
	println("")

	configToml, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	var config servers
	if _, err := toml.Decode(string(configToml), &config); err != nil {
		log.Fatal(err)
	}

	if *dumpConfigFlag {
		fmt.Printf("\nConfig:\n")
		for name, s := range config {
			fmt.Printf("  Server: %s (addr: %s)\n", name, s.Addr)
		}
		fmt.Printf("\n")
	}

	os.Exit(1)
}
