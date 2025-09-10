package formatter

import (
	_ "embed"

	"github.com/netsampler/goflow2/v2/format"
	"github.com/sirupsen/logrus"
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
