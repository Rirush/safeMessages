package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/karrick/tparse"
	"github.com/rirush/safeMessages/protocol"
	"io/ioutil"
	"os"
	"time"
)

const Usage = `Usage:
	certificateIssuer generatePair [pubkey] [privkey]
                      issueCertificate [privkey] [certificate] [validUntil] [description] <uuid>
                      verifyCertificate [pubkey] [certificate] [signature]
                      renewCertificate [privkey] [expiredCertificate] [newCertificate] [validUntil]`

func main() {
	if len(os.Args) == 1 {
		fmt.Println(Usage)
		os.Exit(0)
	}
	switch os.Args[1] {
	case "generatePair":
		if len(os.Args) != 4 {
			fmt.Println(Usage)
			os.Exit(1)
		}
		pubKeyPath := os.Args[2]
		privKeyPath := os.Args[3]
		pubkey, privkey, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(pubKeyPath, pubkey, 0755)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(privKeyPath, privkey, 0755)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	case "issueCertificate":
		if len(os.Args) != 6 && len(os.Args) != 7 {
			fmt.Println(Usage)
			os.Exit(1)
		}
		privKeyPath := os.Args[2]
		key, err := ioutil.ReadFile(privKeyPath)
		if err != nil {
			fmt.Println("Cannot read private key:", err)
			os.Exit(1)
		}
		if len(key) != ed25519.PrivateKeySize {
			fmt.Println("Invalid key, size mismatch")
			os.Exit(1)
		}
		pKey := ed25519.PrivateKey(key)
		certPath := os.Args[3]
		validUntil := os.Args[4]
		t, err := tparse.ParseNow(time.ANSIC, validUntil)
		if err != nil {
			fmt.Println("Cannot parse time:", err)
			os.Exit(1)
		}
		marshalledTime, err := t.MarshalText()
		if err != nil {
			fmt.Println("Cannot marshal time:", err)
			os.Exit(1)
		}
		validUntil = string(marshalledTime)
		description := os.Args[5]
		var serverUuid string
		if len(os.Args) == 6 {
			u, err := uuid.NewRandom()
			if err != nil {
				fmt.Println("Cannot generate UUID:", err)
				os.Exit(1)
			}
			serverUuid = u.String()
		} else {
			u, err := uuid.Parse(os.Args[6])
			if err != nil {
				fmt.Println("Invalid UUID:", err)
				os.Exit(1)
			}
			serverUuid = u.String()
		}
		serverPubKey, serverPrivKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Println("Cannot generate server key:", err)
			os.Exit(1)
		}
		certificate := protocol.ServerCertificate{
			ServerID: serverUuid,
			Expiration: validUntil,
			Description: description,
			SigningKey: serverPubKey,
		}
		marshalledCertificate, err := json.Marshal(certificate)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
		signature := ed25519.Sign(pKey, marshalledCertificate)
		err = ioutil.WriteFile(certPath, marshalledCertificate, 0700)
		if err != nil {
			fmt.Println("Cannot write certificate:", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(certPath + ".priv", serverPrivKey, 0700)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(certPath + ".sig", signature, 0700)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}

	case "verifyCertificate":
		if len(os.Args) != 5 {
			fmt.Println(Usage)
			os.Exit(1)
		}
		pubKeyPath := os.Args[2]
		certPath := os.Args[3]
		signaturePath := os.Args[4]
		pubkeyBytes, err := ioutil.ReadFile(pubKeyPath)
		if err != nil {
			fmt.Println("Cannot read public key:", err)
			os.Exit(1)
		}
		pubkey := ed25519.PublicKey(pubkeyBytes)
		signature, err := ioutil.ReadFile(signaturePath)
		if err != nil {
			fmt.Println("Cannot read signature:", err)
			os.Exit(1)
		}
		certificate, err := ioutil.ReadFile(certPath)
		if err != nil {
			fmt.Println("Cannot read certificate:", err)
			os.Exit(1)
		}
		if ed25519.Verify(pubkey, certificate, signature) {
			cert := protocol.ServerCertificate{}
			json.Unmarshal(certificate, &cert)
			expirationDate, _ := time.Parse(time.RFC3339, cert.Expiration)
			if expirationDate.Before(time.Now()) {
				fmt.Println("Certificate is expired")
			} else {
				fmt.Println("Certificate is valid")
			}
		} else {
			fmt.Println("Certificate is invalid")
		}


	case "renewCertificate":
		if len(os.Args) != 6 {
			fmt.Println(Usage)
			os.Exit(1)
		}
		privKeyPath := os.Args[2]
		privKeyBytes, err := ioutil.ReadFile(privKeyPath)
		if err != nil {
			fmt.Println("Cannot read private key:", err)
			os.Exit(1)
		}
		if len(privKeyBytes) != ed25519.PrivateKeySize {
			fmt.Println("Invalid private key")
			os.Exit(1)
		}
		privKey := ed25519.PrivateKey(privKeyBytes)
		expiredCertPath := os.Args[3]
		expiredCertBytes, err := ioutil.ReadFile(expiredCertPath)
		if err != nil {
			fmt.Println("Cannot read expired certificate:", err)
			os.Exit(1)
		}
		expiredCert := protocol.ServerCertificate{}
		err = json.Unmarshal(expiredCertBytes, &expiredCert)
		if err != nil {
			fmt.Println("Cannot unmarshal certificate:", err)
			os.Exit(1)
		}
		newCertPath := os.Args[4]
		validUntil := os.Args[5]
		t, err := tparse.ParseNow(time.ANSIC, validUntil)
		if err != nil {
			fmt.Println("Cannot parse time:", err)
			os.Exit(1)
		}
		marshalledTime, err := t.MarshalText()
		if err != nil {
			fmt.Println("Cannot marshal time:", err)
			os.Exit(1)
		}
		serverPubKey, serverPrivKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Println("Cannot generate server key:", err)
			os.Exit(1)
		}
		u, err := uuid.Parse(expiredCert.ServerID)
		if err != nil {
			fmt.Println("Invalid UUID:", err)
			os.Exit(1)
		}
		expiredCert.ServerID = u.String()
		newCertificate := protocol.ServerCertificate{
			ServerID:    expiredCert.ServerID,
			Expiration:  string(marshalledTime),
			SigningKey:  serverPubKey,
			Description: expiredCert.Description,
		}
		marshalledCertificate, err := json.Marshal(newCertificate)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
		signature := ed25519.Sign(privKey, marshalledCertificate)
		err = ioutil.WriteFile(newCertPath, marshalledCertificate, 0700)
		if err != nil {
			fmt.Println("Cannot write certificate:", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(newCertPath + ".priv", serverPrivKey, 0700)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(newCertPath + ".sig", signature, 0700)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
	}
}
