package protocol

import "github.com/Rirush/safeMessages/protocol/pb"

var (
	ErrNotImplemented = NewError(&pb.Error{Code: pb.ErrorCode_NOT_IMPLEMENTED, Description: "Method is not implemented"})
	ErrUnauthorized = NewError(&pb.Error{Code: pb.ErrorCode_UNAUTHORIZED, Description: "Authentication is required"})
	ErrUnknownFunction = NewError(&pb.Error{Code: pb.ErrorCode_UNKNOWN_FUNCTION, Description: "Function not found"})
	ErrUnmarshalFailure = NewError(&pb.Error{Code: pb.ErrorCode_UNMARSHAL_FAILURE, Description: "Message unmarshal failed"})
	ErrInvalidArgument = NewError(&pb.Error{Code: pb.ErrorCode_INVALID_ARGUMENT, Description: "Invalid argument was supplied"})
	ErrInvalidDevice = NewError(&pb.Error{Code: pb.ErrorCode_INVALID_DEVICE, Description: "Invalid device was specified"})
	ErrVerificationFailed = NewError(&pb.Error{Code: pb.ErrorCode_VERIFICATION_FAILED, Description: "Device verification failed"})
	ErrInternalServerError = NewError(&pb.Error{Code: pb.ErrorCode_INTERNAL_SERVER_ERROR, Description: "Unexpected error has occurred on the server side"})
	ErrInvalidIdentity = NewError(&pb.Error{Code: pb.ErrorCode_INVALID_IDENTITY, Description: "Invalid identity was specified"})
	ErrUsernameTaken = NewError(&pb.Error{Code: pb.ErrorCode_USERNAME_TAKEN, Description: "Username is already taken"})
	ErrAlreadyAuthorized = NewError(&pb.Error{Code: pb.ErrorCode_ALREADY_AUTHORIZED, Description: "Already authorized"})
)