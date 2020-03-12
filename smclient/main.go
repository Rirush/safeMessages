package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smclient/network/connection"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type Description struct {
	PublicDeviceKey ed25519.PublicKey
	PrivateDeviceKey ed25519.PrivateKey
	DeviceName string
	DeviceAddress uuid.UUID

	PrivateSignatureKey ed25519.PrivateKey
	PrivateExchangeKey []byte
	EncryptionKey []byte
	IdentityAddress uuid.UUID

	KnownIdentities map[uuid.UUID]struct{
		Name string
		ExchangeKey []byte
		SignatureKey ed25519.PublicKey
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("smclient [host] [device]")
		return
	}

	dev := Description{
		KnownIdentities: map[uuid.UUID]struct {
			Name         string
			ExchangeKey  []byte
			SignatureKey ed25519.PublicKey
		}{},
	}
	var conn connection.Conn

	host := os.Args[1]
	device := os.Args[2]
	if _, err := os.Stat(device); os.IsNotExist(err) {
		log.Println("No device descriptor, creating new...")
		publicDeviceKey, privateDeviceKey, _ := ed25519.GenerateKey(nil)
		randBytes := make([]byte, 4)
		_, _ = rand.Read(randBytes)
		randString := "Device " + hex.EncodeToString(randBytes)
		conn, err = connection.Dial(host)
		if err != nil {
			log.Fatalf("Cannot connect to server: %s\n", err)
		}
		id, e, err := conn.Register(randString, publicDeviceKey)
		if err != nil {
			log.Fatalf("Cannot send message to server: %s\n", err)
		}
		if e != nil {
			log.Fatalf("Remote request failed: %s\n", e.Description)
		}
		log.Printf("Registered as %s\n", id)

		dev = Description{
			DeviceAddress: *id,
			DeviceName: randString,
			PublicDeviceKey: publicDeviceKey,
			PrivateDeviceKey: privateDeviceKey,
		}

		fmt.Print("You need an identity to start:\n1) Register\n2) Login\nYour choice: ")
		c := 0
		_, _ = fmt.Scanf("%d\n", &c)
		switch c {
		case 1:
			fmt.Print("Username: ")
			var username, password, name string
			fmt.Scanf("%s\n", &username)
			fmt.Print("Password: ")
			fmt.Scanf("%s\n", &password)
			fmt.Print("Name: ")
			fmt.Scanf("%s\n", &name)
			publicSignatureKey, privateSignatureKey, _ := ed25519.GenerateKey(nil)
			privateKey := make([]byte, 32)
			_, _ = rand.Read(privateKey)
			publicKey, _ := curve25519.X25519(privateKey, curve25519.Basepoint)
			r, e, err := conn.RegisterIdentity(username, name, publicSignatureKey, privateSignatureKey, publicKey, privateKey, password)
			if err != nil {
				log.Fatalf("Connection error: %s\n", err)
			}
			if e != nil {
				log.Fatalf("Cannot register: %s\n", e.Description)
			}
			fmt.Printf("Registered succesfully with address %s\n", r.Address)
			dev.EncryptionKey = r.Key
			dev.PrivateExchangeKey = privateKey
			dev.PrivateSignatureKey = privateSignatureKey
			dev.IdentityAddress = r.Address
			d, _ := json.Marshal(dev)
			_ = ioutil.WriteFile(device, d, 0755)
		case 2:
			fmt.Print("Username: ")
			var username, password string
			fmt.Scanf("%s\n", &username)
			fmt.Print("Password: ")
			fmt.Scanf("%s\n", &password)
			r, e, err := conn.LinkIdentity(username, password)
			if err != nil {
				log.Fatalf("Connection error: %s\n", err)
			}
			if e != nil {
				log.Fatalf("Authorization failed: %s\n", e.Description)
			}
			dev.IdentityAddress = r.Address
			dev.PrivateSignatureKey = r.SignatureKey
			dev.PrivateExchangeKey = r.ExchangeKey
			dev.EncryptionKey = r.EncryptionKey
			d, _ := json.Marshal(dev)
			_ = ioutil.WriteFile(device, d, 0755)
		default:
			log.Fatalln("Invalid selection")
		}
	} else {
		fmt.Println("Authorizing using selected device...")
		data, err := ioutil.ReadFile(device)
		if err != nil {
			log.Fatalf("Cannot read device file: %s\n", err)
		}
		err = json.Unmarshal(data, &dev)
		if err != nil {
			log.Fatalf("Cannot read device file: %s\n", err)
		}
		conn, err = connection.Dial(host)
		if err != nil {
			log.Fatalf("Cannot connect to server: %s\n", err)
		}
		e, err := conn.Authorize(dev.DeviceAddress, dev.PrivateDeviceKey)
		if err != nil {
			log.Fatalf("Connection error: %s\n", err)
		}
		if e != nil {
			log.Fatalf("Authorization failed: %s\n", e.Description)
		}
		fmt.Println("Authorized successfully")
	}

	conn2, _ := connection.Dial(host)
	_, _ = conn2.Authorize(dev.DeviceAddress, dev.PrivateDeviceKey)
	d, err := conn2.ReceiveMessages(dev.IdentityAddress)
	if err != nil {
		log.Fatalf("Cannot receive messages: %s\n", err)
	}

	go func() {
		conn, _ := connection.Dial(host)
		_, _ = conn.Authorize(dev.DeviceAddress, dev.PrivateDeviceKey)
		fmt.Println("Listening for messages")
		for message := range d {
			u, ok := dev.KnownIdentities[message.Sender]
			if !ok {
				i, _, _ := conn.QueryIdentityByAddress(message.Sender)
				u = struct {
					Name         string
					ExchangeKey  []byte
					SignatureKey ed25519.PublicKey
				}{Name: i.Name, ExchangeKey: i.ExchangeKey, SignatureKey: i.SignatureKey}
			}
			secret, _ := curve25519.X25519(dev.PrivateExchangeKey, u.ExchangeKey)
			cp, _ := aes.NewCipher(secret)
			gcm, _ := cipher.NewGCM(cp)
			nonceSize := gcm.NonceSize()
			nonce, ciphertext := message.Data[:nonceSize], message.Data[nonceSize:]
			message.Data, _ = gcm.Open(nil, nonce, ciphertext, nil)
			//g.CryptBlocks(message.Data, message.Data)
			msg := &pb.Message{}
			proto.Unmarshal(message.Data, msg)
			text := msg.Content.(*pb.Message_Text).Text.Text
			log.Printf("(%s) %s> %s\n", message.Sender.String(), u.Name, text)
		}
		log.Fatalln("Listener thread died")
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		data := scanner.Text()
		arguments := strings.SplitN(data, " ", 3)
		if len(arguments) != 2 && len(arguments) != 3 {
			fmt.Println("Invalid command!")
			continue
		}
		switch arguments[0] {
		case "send":
			if len(arguments) != 3 {
				fmt.Println("Invalid arguments!")
				continue
			}
			address, err := uuid.Parse(arguments[1])
			if err != nil {
				fmt.Println("Cannot parse address")
				continue
			}
			u, ok := dev.KnownIdentities[address]
			if !ok {
				i, e, _ := conn.QueryIdentityByAddress(address)
				if e != nil || i == nil {
					fmt.Println("Invalid address!")
					continue
				}
				u = struct {
					Name         string
					ExchangeKey  []byte
					SignatureKey ed25519.PublicKey
				}{Name: i.Name, ExchangeKey: i.ExchangeKey, SignatureKey: i.SignatureKey}
			}
			secret, _ := curve25519.X25519(dev.PrivateExchangeKey, u.ExchangeKey)
			e, err := conn.SendMessage(address, dev.IdentityAddress, arguments[2], secret, dev.PrivateSignatureKey)
			if err != nil {
				fmt.Printf("Transport error: %s\n", err)
				continue
			}
			if e != nil {
				fmt.Printf("Server error: %s\n", e.Description)
			}
		case "find":
			if len(arguments) != 2 {
				fmt.Println("Invalid arguments!")
				continue
			}
			username := arguments[1]
			i, e, err := conn.QueryIdentity(username)
			if err != nil {
				fmt.Println("Transport error:", err)
				continue
			}
			if e != nil {
				fmt.Println("Server error:", e)
				continue
			}
			if i == nil {
				fmt.Println("No such user found!")
			} else {
				fmt.Printf("Address: %s\nName: %s\n", i.Address, i.Name)
			}
		}
	}

	data, _ := json.Marshal(dev)
	_ = ioutil.WriteFile(device, data, 0755)
}
