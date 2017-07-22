package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/mail"
	"net/smtp"
	"os/exec"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type serverConfig struct {
	Ports    []int
	Location string
	Created  time.Time
}

type server struct {
	IP     string       `toml:"ip,omitempty"`
	Config serverConfig `toml:"config"`
}

type servers map[string]server

func main() {
	var tomlBlob = `
# Some comments.
[alpha]
ip = "10.0.0.1"

	[alpha.config]
	Ports = [ 8001, 8002 ]
	Location = "Toronto"
	Created = 1987-07-05T05:45:00Z

[beta]
ip = "10.0.0.2"

	[beta.config]
	Ports = [ 9001, 9002 ]
	Location = "New Jersey"
	Created = 1887-01-05T05:55:00Z
`

	var config servers
	if _, err := toml.Decode(tomlBlob, &config); err != nil {
		log.Fatal(err)
	}

	for _, name := range []string{"alpha", "beta"} {
		s := config[name]
		fmt.Printf("Server: %s (ip: %s) in %s created on %s\n",
			name, s.IP, s.Config.Location,
			s.Config.Created.Format("2006-01-02"))
		fmt.Printf("Ports: %v\n", s.Config.Ports)
	}

	servername := "mail.messagingengine.com:587"
	// servername := "smtp.nps.edu:587"
	// servername := "email-smtp.us-west-2.amazonaws.com:587"
	// servername := "smtp.gmail.com:587"
	// username := "username@example.tld"
	// password := "password"

	const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1
oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD
QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh
xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB
CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl
5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA
8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC
2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit
c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0
j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz
-----END CERTIFICATE-----`

	out, err := exec.Command("date").Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("The date is %s\n", out)

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		log.Panic("failed to parse root certificate")
	}

	host, _, err := net.SplitHostPort(servername)
	if err != nil {
		log.Panic(err)
	}

	// auth := smtp.PlainAuth("", username, password, host)

	tlsconfig := &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs:    roots,
		ServerName: host,
	}

	c, err := smtp.Dial(servername)
	if err != nil {
		log.Panic(err)
	}

	c.StartTLS(tlsconfig)

	state, ok := c.TLSConnectionState()
	if !ok {
		log.Panic("STARTTLS Failed")
	}

	for _, cert := range state.PeerCertificates {
		fmt.Printf("------------\n")
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

		fmt.Printf("------------\n")
		fmt.Printf("\n")
	}

	//	if err = c.Auth(auth); err != nil {
	//		log.Panic(err)
	//	}

	msg := `Date: Mon, 23 Jun 2015 11:40:36 -0400
From: Gopher <from@example.com>
To: Another Gopher <to@example.com>
Subject: Gophers at Gophercon
Cc: aa@example.com, bb@example.com, cc@example.com
Cc: caa@example.com, cbb@example.com, ccc@example.com
Bcc: baa@example.com, bbb@example.com, bcc@example.com
Bcc: bbaa@example.com, bbbb@example.com, bbcc@example.com
Message-ID: <ex@example.org>
Organization: Example

Message body
`

	r := strings.NewReader(msg)
	m, err := mail.ReadMessage(r)
	if err != nil {
		log.Fatal(err)
	}

	header := m.Header

	fromaddress := header.Get("From")
	toaddresses := strings.Split(header.Get("To"), ",")
	toaddresses = append(toaddresses, strings.Split(header.Get("Cc"), ",")...)
	toaddresses = append(toaddresses, strings.Split(header.Get("Bcc"), ",")...)

	fmt.Println("Send email from:", fromaddress)
	fmt.Println("Send email to:", strings.Join(toaddresses, ", "))
	fmt.Println("--")

	fmt.Println("-- Email")
	for k, v := range header {
		if "Bcc" != k {
			for _, h := range v {
				fmt.Printf("%s: %s\n", k, h)
			}
		}
	}
	fmt.Println("")
	body, err := ioutil.ReadAll(m.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", body)
	fmt.Println("--")

	//
	//	err = c.Mail(fromaddress)
	//	if err != nil {
	//		log.Panic(err)
	//	}
	//
	//	err = c.Rcpt(toaddress)
	//	if err != nil {
	//		log.Panic(err)
	//	}
	//
	//	w, err := c.Data()
	//	if err != nil {
	//		log.Panic(err)
	//	}
	//
	//	_, err = w.Write([]byte(message))
	//	if err != nil {
	//		log.Panic(err)
	//	}
	//
	//	err = w.Close()
	//	if err != nil {
	//		log.Panic(err)
	//	}
	//
	//	err = c.Quit()
	//	if err != nil {
	//		log.Panic(err)
	//	}
}
