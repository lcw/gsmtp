package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
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
var defaultLogFile = path.Join(userHomeDir(), ".gsmtp.log")

var configFileFlag = flag.String("config", defaultConfigFile,
	"File to read configuration from")
var logFileFlag = flag.String("logfile", defaultLogFile,
	"File to write log to")
var fromFlag = flag.String("f", "", "From address to select server")
var accountFlag = flag.String("account", "", "Server to send email through")
var debugFlag = flag.Bool("debug", false, "Verbose")
var serverinfoFlag = flag.Bool("serverinfo", false, "Print server info and quit")
var _ = flag.Bool("oi", false, "Ignored sendmail flag")

func printFlags() {
	println("")
	println("Flags:")
	println("     account:", *accountFlag)
	println("      config:", *configFileFlag)
	println("       debug:", *debugFlag)
	println("           f:", *fromFlag)
	println("     logfile:", *logFileFlag)
	println("  serverinfo:", *serverinfoFlag)
}

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

func printConfig(config gsmtpConfig) {
	println("")
	println("Config:")
	println("  Default server:", config.DefaultServer)
	for name, s := range config.Servers {
		println("  ~~~~~~~~~")
		println("    Server:", name)
		println("      Addr:", s.Addr)
		println("      From:", s.From)
		println("  Username:", s.Username)
		println("  PassEval:", s.PassEval)
		println("   RootPEM:\n", s.RootPEM)
	}
}

func printServerInfo(config gsmtpConfig) error {
	for name, s := range config.Servers {
		fmt.Printf("\n------------------------------------------------------------------------\n")
		fmt.Printf("  Server info for: %s\n", name)
		fmt.Printf("------------------------------------------------------------------------\n")

		host, _, err := net.SplitHostPort(s.Addr)
		if err != nil {
			return err
		}

		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}

		c, err := smtp.Dial(s.Addr)
		if err != nil {
			return err
		}
		defer c.Close()

		if ok, _ := c.Extension("STARTTLS"); ok {
			if err = c.StartTLS(config); err != nil {
				return err
			}
		} else {
			return errors.New("Server does not have the extension STARTTLS")
		}

		state, ok := c.TLSConnectionState()
		if !ok {
			return errors.New("Problem getting TLS state")
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

		if err = c.Quit(); err != nil {
			return err
		}

		fmt.Printf("------------------------------------------------------------------------\n\n\n")
	}

	return nil
}

func sendMail(rootPEM string, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return errors.New("Failed to parse root certificate")
	}

	config := &tls.Config{
		ServerName: host,
		RootCAs:    roots,
	}

	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(config); err != nil {
			return err
		}
	} else {
		err = errors.New("Server does not have the extension STARTTLS")
		return err
	}

	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}

func getAuth(s server) (smtp.Auth, error) {
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return nil, err
	}

	password, err := exec.Command(s.PassEval[0], s.PassEval[1:]...).Output()
	if err != nil {
		return nil, err
	}

	auth := smtp.PlainAuth("", s.Username, string(password), host)

	return auth, nil
}

func getServerName(config gsmtpConfig) string {
	n := *accountFlag
	if n == "" {
		n = config.DefaultServer
		if *fromFlag != "" {
			for name, s := range config.Servers {
				if strings.Compare(s.From, *fromFlag) == 0 {
					n = name
					break
				}
			}
		}
	}
	return n
}

func parseMail(r io.Reader) (string, []string, []byte, error) {
	m, err := mail.ReadMessage(r)
	if err != nil {
		return "", nil, nil, err
	}

	// Parse the from address
	f, err := mail.ParseAddress(m.Header.Get("From"))
	if err != nil {
		return "", nil, nil, err
	}
	from := f.Address

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

	// Parse the to addresses
	tal, err := mail.ParseAddressList(l)
	if err != nil {
		return "", nil, nil, err
	}
	to := make([]string, len(tal))
	for i, t := range tal {
		to[i] = t.Address
	}

	// Build the email to send (with the Bcc headers removed)
	var msg bytes.Buffer
	for k, v := range m.Header {
		if "Bcc" != k {
			for _, h := range v {
				_, err := msg.WriteString(fmt.Sprintf("%s: %s\n", k, h))
				if err != nil {
					return "", nil, nil, err
				}
			}
		}
	}
	_, err = msg.WriteString("\n")
	if err != nil {
		return "", nil, nil, err
	}
	_, err = msg.ReadFrom(m.Body)
	if err != nil {
		return "", nil, nil, err
	}

	return from, to, msg.Bytes(), err
}

func main() {
	flag.Parse()

	logFile, err := os.OpenFile(*logFileFlag, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	log.SetOutput(logFile)

	if len(flag.Args()) > 0 {
		log.Printf("Warning: unused arguments %v\n", flag.Args())
	}

	configToml, err := ioutil.ReadFile(*configFileFlag)
	if err != nil {
		log.Panic(err)
	}

	var config gsmtpConfig
	if _, err := toml.Decode(string(configToml), &config); err != nil {
		log.Panic(err)
	}

	if *debugFlag {
		printFlags()
		printConfig(config)
	}

	if *serverinfoFlag {
		err := printServerInfo(config)
		if err != nil {
			log.Panic(err)
		} else {
			log.Println("Got server info")
			os.Exit(0)
		}
	}

	sn := getServerName(config)
	s := config.Servers[sn]
	auth, err := getAuth(s)
	if err != nil {
		log.Panic(err)
	}

	r := bufio.NewReader(os.Stdin)
	from, to, msg, err := parseMail(r)
	if err != nil {
		log.Panic(err)
	}

	if *debugFlag {
		println("Selected Account:", sn)
		println("Auth:", auth)
		println("Send email from:", from)
		println("Send email to:", strings.Join(to, ", "))
		fmt.Printf("Mail:\"\"\"\n%s\"\"\"\n", string(msg))
	}

	err = sendMail(s.RootPEM, s.Addr, auth, from, to, msg)
	if err != nil {
		log.Panic(err)
	}

	log.Printf("[SENT] from:%s to:%s", from, strings.Join(to, ", "))
}
