package protocol

import "github.com/Rirush/safeMessages/protocol/pb"

var (
	ErrNotImplemented = NewError(&pb.Error{Code: pb.ErrorCode_NOT_IMPLEMENTED, Description: "Method is not implemented"})
	ErrUnauthorized = NewError(&pb.Error{Code: pb.ErrorCode_UNAUTHORIZED, Description: "Authentication is required"})
	ErrUnknownFunction = NewError(&pb.Error{Code: pb.ErrorCode_UNKNOWN_FUNCTION, Description: "Function not found"})
)