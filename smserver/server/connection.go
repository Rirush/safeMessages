package server

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/event"
	"github.com/golang/protobuf/proto"
	"io"
	"log"
)



func startConnectionHandler(conn *tls.Conn) {
	session := event.SessionData{
		Conn: conn,
	}

	defer func() {
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	for {
		// Receiver logic:
		size, err := binary.ReadUvarint(reader)
		if err != nil {
			log.Printf("Error while reading from connection: %e\n", err)
			return
		}
		log.Printf("Preparing to read %d bytes\n", size)
		buf := make([]byte, size)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			log.Printf("Error while reading data: %e\n", err)
			return
		}
		// Store message for possible signature verification later
		//session.lastMessage = buf
		msg := pb.Packet{}
		if err = proto.Unmarshal(buf, &msg); err != nil {
			log.Printf("Cannot decode message: %e\n", err)
			return
		}

		// Handler and replier logic:
		response, err := event.HandlePacket(&session, &msg)
		if err != nil {
			log.Printf("Message processing failed: %e\n", err)
			return
		}
		data, err := proto.Marshal(&response)
		if err != nil {
			log.Printf("Cannot encode protobuf: %e\n", err)
			return
		}
		buf = make([]byte, 10)
		n := binary.PutUvarint(buf, uint64(len(data)))
		_, err = conn.Write(append(buf[:n], data...))
		if err != nil {
			log.Printf("Cannot reply to request: %e\n", err)
			return
		}
	}
}