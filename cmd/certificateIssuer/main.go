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

func WriteKeysToFile(pubkey, privkey []byte, pubkeyPath, privkeyPath string) {
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(pubkeyPath, pubkey, 0700)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(privkeyPath, privkey, 0700)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func FormCertificate(validUntil, description, serverUUID string) (protocol.ServerCertificate, ed25519.PrivateKey) {
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

	if serverUUID == "" {
		u, err := uuid.NewRandom()
		if err != nil {
			fmt.Println("Cannot generate UUID:", err)
			os.Exit(1)
		}
		serverUUID = u.String()
	} else {
		u, err := uuid.Parse(serverUUID)
		if err != nil {
			fmt.Println("Invalid UUID:", err)
			os.Exit(1)
		}
		serverUUID = u.String()
	}

	serverPubKey, serverPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("Cannot generate server key:", err)
		os.Exit(1)
	}

	return protocol.ServerCertificate{
		ServerID:    serverUUID,
		Expiration:  validUntil,
		SigningKey:  serverPubKey,
		Description: description,
	}, serverPrivKey
}

func WriteCertificateFiles(certificate, signature, privKey []byte, basePath string) {
	err := ioutil.WriteFile(basePath, certificate, 0700)
	if err != nil {
		fmt.Println("Cannot write certificate:", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(basePath+".priv", privKey, 0700)
	if err != nil {
		fmt.Println("Cannot marshal certificate:", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(basePath+".sig", signature, 0700)
	if err != nil {
		fmt.Println("Cannot marshal certificate:", err)
		os.Exit(1)
	}
}

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
		pubkey, privkey, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Println("Cannot create key pair:", err)
			os.Exit(1)
		}
		WriteKeysToFile(pubkey, privkey, os.Args[2], os.Args[3])
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
		serverUUID := ""
		if len(os.Args) == 7 {
			serverUUID = os.Args[6]
		}

		certificate, serverPrivKey := FormCertificate(os.Args[4], os.Args[5], serverUUID)
		marshalledCertificate, err := json.Marshal(certificate)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
		signature := ed25519.Sign(pKey, marshalledCertificate)

		WriteCertificateFiles(marshalledCertificate, signature, serverPrivKey, os.Args[3])

	case "verifyCertificate":
		if len(os.Args) != 5 {
			fmt.Println(Usage)
			os.Exit(1)
		}

		pubkeyBytes, err := ioutil.ReadFile(os.Args[2])
		if err != nil {
			fmt.Println("Cannot read public key:", err)
			os.Exit(1)
		}
		pubkey := ed25519.PublicKey(pubkeyBytes)
		signature, err := ioutil.ReadFile(os.Args[4])
		if err != nil {
			fmt.Println("Cannot read signature:", err)
			os.Exit(1)
		}
		certificate, err := ioutil.ReadFile(os.Args[3])
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
				os.Exit(1)
			} else {
				fmt.Println("Certificate is valid")
			}
		} else {
			fmt.Println("Certificate is invalid")
			os.Exit(2)
		}

	case "renewCertificate":
		if len(os.Args) != 6 {
			fmt.Println(Usage)
			os.Exit(1)
		}

		privKeyBytes, err := ioutil.ReadFile(os.Args[2])
		if err != nil {
			fmt.Println("Cannot read private key:", err)
			os.Exit(1)
		}
		if len(privKeyBytes) != ed25519.PrivateKeySize {
			fmt.Println("Invalid private key")
			os.Exit(1)
		}
		privKey := ed25519.PrivateKey(privKeyBytes)
		expiredCertBytes, err := ioutil.ReadFile(os.Args[3])
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

		certificate, serverPrivKey := FormCertificate(os.Args[5], expiredCert.Description, expiredCert.ServerID)
		marshalledCertificate, err := json.Marshal(certificate)
		if err != nil {
			fmt.Println("Cannot marshal certificate:", err)
			os.Exit(1)
		}
		signature := ed25519.Sign(privKey, marshalledCertificate)

		WriteCertificateFiles(marshalledCertificate, signature, serverPrivKey, os.Args[4])
	}
}
