package formatter

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/netsampler/goflow2/v2/format"
	gf2proto "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/sirupsen/logrus"
	"github.com/synfinatic/netflow2ng/proto"
	googleproto "google.golang.org/protobuf/proto"
)

const (
	PROTO_REMAPPED_IN_BYTES  = 200
	PROTO_REMAPPED_IN_PKTS   = 201
	PROTO_REMAPPED_OUT_BYTES = 202
	PROTO_REMAPPED_OUT_PKTS  = 203
)

//go:embed mapping.yaml
var MappingYaml string
var log *logrus.Logger //nolint:unused

func SetLogger(l *logrus.Logger) {
	log = l
}

func init() {
	format.RegisterFormatDriver("ntopjson", &NtopngJson{})
	format.RegisterFormatDriver("ntoptlv", &NtopngTlv{})
}

func castToExtendedFlowMsg(data interface{}) (*proto.ExtendedFlowMessage, error) {

	ppm, ok := data.(*gf2proto.ProtoProducerMessage)
	if !ok {
		return nil, errors.New("could not cast Format data to ProtoProducerMessage")
	}

	// Marshal to binary
	bin, err := googleproto.Marshal(ppm)
	if err != nil {
		return nil, fmt.Errorf("could not marshal ProtoProducerMessage to binary: %w", err)
	}
	// Unmarshal into your custom struct
	efm := &proto.ExtendedFlowMessage{}
	if err := googleproto.Unmarshal(bin, efm); err != nil {
		return nil, fmt.Errorf("could not unmarshal binary to ExtendedFlowMsg: %w", err)
	}

	// Need to assign the BaseFlow field explicitly, as it is not Unmarshalled automatically.
	efm.BaseFlow = &ppm.FlowMessage

	return efm, nil
}
