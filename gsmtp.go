package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/smtp"
	"os"
	"path"
	"runtime"
	"strings"

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
var from = flag.String("f", "", "From address to select server")
var account = flag.String("account", "", "Server to send email through")
var debug = flag.Bool("debug", false, "Verbose")
var serverinfo = flag.Bool("serverinfo", false, "Print server info and quit")
var _ = flag.Bool("oi", false, "Ignored sendmail flag")

type server struct {
	Addr    string `toml:"address,omitempty"`
	From    string `toml:"from"`
	RootPEM string `toml:"rootPEM,omitempty"`
}
type gsmtpConfig struct {
	DefaultServer string `toml:"default"`
	Servers       map[string]server
}

func printServerInfo(config gsmtpConfig) {
	for name, s := range config.Servers {
		fmt.Printf("\n------------------------------------------------------------------------\n")
		fmt.Printf("  Server info for: %s\n", name)
		fmt.Printf("------------------------------------------------------------------------\n")

		host, _, err := net.SplitHostPort(s.Addr)
		if err != nil {
			log.Panic(err)
		}

		tlsconfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}

		c, err := smtp.Dial(s.Addr)
		if err != nil {
			log.Panic(err)
		}
		defer func() {
			if err := c.Close(); err != nil {
				log.Panic(err)
			}
		}()

		c.StartTLS(tlsconfig)

		state, ok := c.TLSConnectionState()
		if !ok {
			log.Panic("STARTTLS Failed")
		}

		for _, cert := range state.PeerCertificates {
			for i, dnsname := range cert.DNSNames {
				fmt.Printf("DNSnames[%d]: %s\n", i, dnsname)
			}
			for i, value := range cert.CRLDistributionPoints {
				fmt.Printf("CRLDistributionPoints[%d]: %s\n", i, value)
			}
			for i, value := range cert.IssuingCertificateURL {
				fmt.Printf("IssuingCertificateURL[%d]: %s\n", i, value)
			}
			hash := sha256.New()
			hash.Write(cert.Raw)
			fingerprint := fmt.Sprintf("%X", hash.Sum(nil))
			fmt.Printf("SHA-256 Fingerprint:\n %s\n", fingerprint)

			pemBlock := pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			fmt.Print(string(pem.EncodeToMemory(&pemBlock)))

			fmt.Printf("\n")
		}

		fmt.Printf("------------------------------------------------------------------------\n\n\n")
	}
}

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

	var config gsmtpConfig
	if _, err := toml.Decode(string(configToml), &config); err != nil {
		log.Fatal(err)
	}

	if *debug {
		fmt.Printf("\nConfig:\n")
		fmt.Printf("  Default server: %s\n", config.DefaultServer)
		for name, s := range config.Servers {
			fmt.Printf("  Server: %s\n", name)
			fmt.Printf("    Addr: %s\n", s.Addr)
			fmt.Printf("    From: %s\n", s.From)
			if s.RootPEM != "" {
				fmt.Printf("    RootPEM:\n%s\n", s.RootPEM)
			}
		}
		fmt.Printf("\n")
	}

	if *serverinfo {
		printServerInfo(config)
		os.Exit(0)
	}

	// Set the account
	if *account == "" {
		*account = config.DefaultServer
		if *from != "" {
			for name, s := range config.Servers {
				if strings.Compare(s.From, *from) == 0 {
					*account = name
					break
				}
			}
		}
	}

	if *debug {
		fmt.Printf("\nSelected Account:%s\n", *account)
	}

	os.Exit(1)
}
