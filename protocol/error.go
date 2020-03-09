package protocol

import "github.com/Rirush/safeMessages/protocol/pb"

var (
	ErrNotImplemented = NewError(&pb.Error{Code: pb.ErrorCode_NOT_IMPLEMENTED, Description: "Method is not implemented"})
)