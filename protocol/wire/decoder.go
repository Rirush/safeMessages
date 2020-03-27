package wire

import (
	"bufio"
	"encoding/binary"
	"github.com/Rirush/safeMessages/protocol/types"
	"google.golang.org/protobuf/proto"
	"io"
)

func DecodeRequestFromStream(src *bufio.Reader) (packet *types.Request, err error) {
	size, err := binary.ReadUvarint(src)
	if err != nil {
		return
	}
	buf := make([]byte, size)
	_, err = io.ReadFull(src, buf)
	if err != nil {
		return
	}
	err = proto.Unmarshal(buf, packet)
	return
}

func DecodeResponseFromStream(src *bufio.Reader) (packet *types.Response, err error) {
	size, err := binary.ReadUvarint(src)
	if err != nil {
		return
	}
	buf := make([]byte, size)
	_, err = io.ReadFull(src, buf)
	if err != nil {
		return
	}
	err = proto.Unmarshal(buf, packet)
	return
}
