package wire

import (
	"github.com/Rirush/safeMessages/protocol/types"
	"google.golang.org/protobuf/proto"
)

func CreateRequest(method types.RequestType, body proto.Message) *types.Request {
	encodedBody, _ := proto.Marshal(body)
	return &types.Request{
		Type: method,
		Data: encodedBody,
	}
}

func CreateResponse(body proto.Message) *types.Response {
	encodedBody, _ := proto.Marshal(body)
	return &types.Response{
		Result: &types.Response_Response{
			Response: encodedBody,
		},
	}
}

func CreateErrorResponse(err *types.Error) *types.Response {
	return &types.Response{
		Result: &types.Response_Error{
			Error: err,
		},
	}
}

func CreateError(code types.ErrorCode, description string) *types.Error {
	return &types.Error{
		Code: code,
		Description: description,
	}
}