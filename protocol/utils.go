package protocol

import (
	"crypto/ed25519"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/golang/protobuf/proto"
)

func NewReply(result proto.Message) pb.Reply {
	// TODO: check when proto.Marshal fails
	data, _ := proto.Marshal(result)
	return pb.Reply{Status:&pb.Reply_Result{Result:data}}
}

func NewError(error *pb.Error) pb.Reply {
	return pb.Reply{Status:&pb.Reply_Error{Error:error}}
}

func CompareBytes(arrayA, arrayB []byte) bool {
	if len(arrayA) != len(arrayB) {
		return false
	}
	for i, b := range arrayA {
		if b != arrayB[i] {
			return false
		}
	}
	return true
}

func VerifySignature(message *pb.Packet, key ed25519.PublicKey) bool {
	return ed25519.Verify(key, message.Data, message.Signature)
}