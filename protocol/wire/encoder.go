package wire

import (
	"encoding/binary"
	"google.golang.org/protobuf/proto"
	"io"
)

func EncodePacketToStream(dest io.Writer, packet proto.Message) error {
	data, _ := proto.Marshal(packet)
	varintBuf := make([]byte, 12)
	n := binary.PutUvarint(varintBuf, uint64(len(data)))
	_, err := dest.Write(varintBuf[:n])
	if err != nil {
		return err
	}
	_, err = dest.Write(data)
	return err
}
