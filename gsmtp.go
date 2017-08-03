package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
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

var configFileFlag = flag.String("config", defaultConfigFile,
	"File to read configuration from")
var fromFlag = flag.String("f", "", "From address to select server")
var accountFlag = flag.String("account", "", "Server to send email through")
var debugFlag = flag.Bool("debug", false, "Verbose")
var serverinfoFlag = flag.Bool("serverinfo", false, "Print server info and quit")
var _ = flag.Bool("oi", false, "Ignored sendmail flag")

type server struct {
	Addr     string   `toml:"address,omitempty"`
	From     string   `toml:"from"`
	Username string   `toml:"username"`
	PassEval []string `toml:"passwordeval"`
	RootPEM  string   `toml:"rootPEM,omitempty"`
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

	if *debugFlag {
		println("Flags:")
		println("  Debug:", *debugFlag)
		println("  Reading config file:", *configFileFlag)
		println("")
	}

	configToml, err := ioutil.ReadFile(*configFileFlag)
	if err != nil {
		log.Fatal(err)
	}

	var config gsmtpConfig
	if _, err := toml.Decode(string(configToml), &config); err != nil {
		log.Fatal(err)
	}

	if *debugFlag {
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

	if *serverinfoFlag {
		printServerInfo(config)
		os.Exit(0)
	}

	// Set the account
	if *accountFlag == "" {
		*accountFlag = config.DefaultServer
		if *fromFlag != "" {
			for name, s := range config.Servers {
				if strings.Compare(s.From, *fromFlag) == 0 {
					*accountFlag = name
					break
				}
			}
		}
	}

	if *debugFlag {
		fmt.Printf("\nSelected Account:%s\n", *accountFlag)
	}

	s := config.Servers[*accountFlag]

	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		log.Panic(err)
	}

	password, err := exec.Command(s.PassEval[0], s.PassEval[1:]...).Output()
	if err != nil {
		log.Fatal(err)
	}

	if *debugFlag {
		fmt.Printf("The host is: %s\n", host)
		fmt.Printf("The password is: %s\n", password)
	}

	// parse email
	r := bufio.NewReader(os.Stdin)
	m, err := mail.ReadMessage(r)
	if err != nil {
		log.Fatal(err)
	}

	f, err := mail.ParseAddress(m.Header.Get("From"))
	if err != nil {
		log.Fatal(err)
	}

	// Build a list of names to send email to
	l := ""
	for k, v := range m.Header {
		if "To" == k || "Cc" == k || "Bcc" == k {
			if l == "" {
				l = strings.Join(v, ",")
			} else {
				l += ", " + strings.Join(v, ",")
			}
		}
	}

	// parse the to addresses
	t, err := mail.ParseAddressList(l)
	if err != nil {
		log.Fatal(err)
	}

	//  build the email to send (with the Bcc headers removed)
	var e bytes.Buffer

	for k, v := range m.Header {
		if "Bcc" != k {
			for _, h := range v {
				_, err := e.WriteString(fmt.Sprintf("%s: %s\n", k, h))
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
	_, err = e.WriteString("\n")
	if err != nil {
		log.Fatal(err)
	}
	_, err = e.ReadFrom(m.Body)
	if err != nil {
		log.Fatal(err)
	}

	if *debugFlag {
		fmt.Println("Send email from:", f)
		fmt.Println("Send email to:")
		for _, v := range t {
			fmt.Println(v.Name, v.Address)
		}
		fmt.Println("--")

		fmt.Println("-- Email")
		fmt.Println(e.String())
		fmt.Println("--")
	}

	os.Exit(1)
}
