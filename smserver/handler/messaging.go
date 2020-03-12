package handler

import (
	"encoding/binary"
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/event"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"sync"
	"time"
)

func CreateChat(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	/*request := pb.CreateChat{}
	err := DecodeMessage(message, &request)
	if err != nil {
		return protocol.ErrUnmarshalFailure, nil
	}
	switch request.ChatType.(type) {
	case *pb.CreateChat_Private:

	default:
		return protocol.ErrNotImplemented, nil
	}*/
	return protocol.ErrNotImplemented, nil
}

func JoinChat(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func PendingChats(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func ChatManagement(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func SendMessage(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	address, err := uuid.FromBytes(message.Destination)
	if err != nil {
		return protocol.ErrInvalidIdentity, nil
	}
	msg := pb.EncapsulatedMessage{
		Sender:    message.Source,
		Receiver:  message.Destination,
		Signature: message.Signature,
		Message:   message.Data,
		SentAt:    time.Now().String(),
	}
	bytes, err := proto.Marshal(&msg)
	if err != nil {
		return protocol.ErrInternalServerError, nil
	}
	_ = globalPublisher.Publish("message." + address.String(), bytes)
	return protocol.NewReply(&pb.SendMessageReply{}), nil
}

func EditMessage(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func ListenForEvents(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	conn, err := nats.Connect(connectionAddress)
	if err != nil {
		return protocol.ErrInternalServerError, nil
	}
	source, err := uuid.FromBytes(message.Source)
	exitMutex := sync.Mutex{}
	exitMutex.Lock()
	sub, err := conn.Subscribe("message." + source.String(), func(msg *nats.Msg) {
		// Assume that the data in the message is perfect and just forward it to clients
		e := pb.Event{
			Type: pb.EventType_MESSAGE,
			Data: msg.Data,
		}
		// Assume it can't fail
		data, _ := proto.Marshal(&e)
		buf := make([]byte, 11)
		n := binary.PutUvarint(buf, uint64(len(data)))
		_, _ = session.Conn.Write(buf[:n])
		_, err := session.Conn.Write(data)
		if err != nil {
			// Client is dead
			exitMutex.Unlock()
		}
	})
	if err != nil {
		return protocol.ErrInternalServerError, nil
	}
	exitMutex.Lock()
	_ = sub.Unsubscribe()
	exitMutex.Unlock()
	// This one never actually returns to the client
	return protocol.ErrNotImplemented, nil
}
