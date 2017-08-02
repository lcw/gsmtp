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
var debug = flag.Bool("debug", false, "Verbose")
var _ = flag.Bool("oi", false, "Ignored sendmail flag")

type server struct {
	Addr string `toml:"address,omitempty"`
}
type servers map[string]server

func main() {
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: unused arguments %v\n", flag.Args())
	}

	if *debug {
		println("Flags:")
		println("  Debug:", *debug)
		println("  Reading config file:", *configFile)
		println("")
	}

	configToml, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	var config servers
	if _, err := toml.Decode(string(configToml), &config); err != nil {
		log.Fatal(err)
	}

	if *debug {
		fmt.Printf("\nConfig:\n")
		for name, s := range config {
			fmt.Printf("  Server: %s (addr: %s)\n", name, s.Addr)
		}
		fmt.Printf("\n")
	}

	os.Exit(1)
}
