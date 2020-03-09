package protocol

import (
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