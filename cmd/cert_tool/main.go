package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

var poisonExtension = pkix.Extension{
	Id:    []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
	Critical: true,
	Value:    []byte{0x05, 0x00},
}

func main() {
	certType := flag.String("type", "root", "Type of certificate to create: root, intermediate, delegate")
	commonName := flag.String("cn", "", "Common Name for the certificate")
	prefix := flag.String("prefix", "", "Prefix for the certificate files")
	b64 := flag.String("b64", "no", "Create base64 encoded certificate file (yes/no)")
	flag.Parse()

	if *commonName == "" {
		fmt.Println("Common Name is required")
		os.Exit(1)
	}

	var parentCert *x509.Certificate
	var parentKey *ecdsa.PrivateKey

	if *certType == "root" {
		_, _ = createCertificate(*commonName, *prefix, *b64, nil, nil)
	} else if *certType == "intermediate" {
		parentCert, parentKey = loadCertificateAndKey("root_cert.pem", "root_key.pem")
		_, _ = createCertificate(*commonName, *prefix, *b64, parentCert, parentKey)
	} else if *certType == "delegate" {
		parentCert, parentKey = loadCertificateAndKey("intermediate_cert.pem", "intermediate_key.pem")
		createPreCertificate(*commonName, *prefix, *b64, parentCert, parentKey)
	} else {
		fmt.Println("Invalid certificate type. Choose from: root, intermediate, delegate")
		os.Exit(1)
	}
}

func createCertificate(commonName string, prefix string, b64 string, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	if parentCert == nil {
		parentCert = tmpl
		parentKey = priv
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &priv.PublicKey, parentKey)
	if err != nil {
		fmt.Printf("Failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	certFile, err := os.Create(fmt.Sprintf("%s_cert.pem", prefix))
	if err != nil {
		fmt.Printf("Failed to create certificate file: %v\n", err)
		os.Exit(1)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		fmt.Printf("Failed to write certificate: %v\n", err)
		os.Exit(1)
	}

	if b64 == "yes" {
		createBase64File(prefix, certBytes)
	}

	keyFile, err := os.Create(fmt.Sprintf("%s_key.pem", prefix))
	if err != nil {
		fmt.Printf("Failed to create key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	x509EncodedKey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Printf("Failed to marshal private key: %v\n", err)
		os.Exit(1)
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509EncodedKey})
	if err != nil {
		fmt.Printf("Failed to write key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate and key created for %s\n", commonName)
	return tmpl, priv
}

func createPreCertificate(commonName string, prefix string, b64 string, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		Extensions:            []pkix.Extension{poisonExtension},
	}

	if parentCert == nil || parentKey == nil {
		fmt.Println("Parent certificate and key are required for creating a pre-certificate")
		os.Exit(1)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &priv.PublicKey, parentKey)
	if err != nil {
		fmt.Printf("Failed to create pre-certificate: %v\n", err)
		os.Exit(1)
	}

	certFile, err := os.Create(fmt.Sprintf("%s_precert.pem", prefix))
	if err != nil {
		fmt.Printf("Failed to create pre-certificate file: %v\n", err)
		os.Exit(1)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		fmt.Printf("Failed to write pre-certificate: %v\n", err)
		os.Exit(1)
	}

	if b64 == "yes" {
		createBase64File(prefix, certBytes)
	}

	keyFile, err := os.Create(fmt.Sprintf("%s_key.pem", prefix))
	if err != nil {
		fmt.Printf("Failed to create key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	x509EncodedKey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Printf("Failed to marshal private key: %v\n", err)
		os.Exit(1)
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509EncodedKey})
	if err != nil {
		fmt.Printf("Failed to write key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Pre-certificate and key created for %s\n", commonName)
}

func loadCertificateAndKey(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey) {
	certFile, err := os.Open(certPath)
	if err != nil {
		fmt.Printf("Failed to open certificate file: %v\n", err)
		os.Exit(1)
	}
	defer certFile.Close()

	certBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		fmt.Printf("Failed to read certificate file: %v\n", err)
		os.Exit(1)
	}

	certPem, _ := pem.Decode(certBytes)
	if certPem == nil {
		fmt.Println("Failed to decode certificate PEM")
		os.Exit(1)
	}
	if certPem == nil {
		fmt.Println("Failed to decode certificate PEM")
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse certificate: %v\n", err)
		os.Exit(1)
	}

	keyFile, err := os.Open(keyPath)
	if err != nil {
		fmt.Printf("Failed to open key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	keyBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		fmt.Printf("Failed to read key file: %v\n", err)
		os.Exit(1)
	}
	
	keyPem, _ := pem.Decode(keyBytes)
	if keyPem == nil {
		fmt.Println("Failed to decode key PEM")
		os.Exit(1)
	}
	if keyPem == nil {
		fmt.Println("Failed to decode key PEM")
		os.Exit(1)
	}

	key, err := x509.ParseECPrivateKey(keyPem.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse private key: %v\n", err)
		os.Exit(1)
	}

	return cert, key
}

func createBase64File(prefix string, certBytes []byte) {
	encodedCert := base64.StdEncoding.EncodeToString(certBytes)

	b64File, err := os.Create(fmt.Sprintf("%s_cert.b64", prefix))
	if err != nil {
		fmt.Printf("Failed to create base64 certificate file: %v\n", err)
		os.Exit(1)
	}
	defer b64File.Close()

	_, err = b64File.WriteString(encodedCert)
	if err != nil {
		fmt.Printf("Failed to write base64 certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Base64 encoded certificate created for %s\n", prefix)
}