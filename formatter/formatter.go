package formatter

import (
	"github.com/netsampler/goflow2/v2/format"
	"github.com/sirupsen/logrus"
)

const (
	PROTO_REMAPPED_IN_BYTES  = 200
	PROTO_REMAPPED_IN_PKTS   = 201
	PROTO_REMAPPED_OUT_BYTES = 202
	PROTO_REMAPPED_OUT_PKTS  = 203
)

// goflow2 allows some remapping of fields. We use this trick to save IN_BYTES/PKTS
// and OUT_BYTES/PKTS into custom fields in the protobuf message so that are not lost.
var MappingYamlStr = `
formatter:
  fields: # list of fields to format in JSON
    - type
    - time_received_ns
    - sequence_num
    - sampling_rate
    - sampler_address
    - time_flow_start_ns
    - time_flow_end_ns
    - bytes
    - packets
    - in_bytes
    - in_packets
    - out_bytes
    - out_packets
    - src_addr
    - src_net
    - dst_addr
    - dst_net
    - etype
    - proto
    - src_port
    - dst_port
    - in_if
    - out_if
    - src_mac
    - dst_mac
  key:
    - sampler_address
  protobuf: # manual protobuf fields addition
    - name: in_bytes
      index: 200 # keep in sych with NFv9_REMAPPED_IN_BYTES
      type: varint
    - name: in_packets
      index: 201 # keep in sych with NFv9_REMAPPED_IN_PKTS
      type: varint
    - name: out_bytes
      index: 202 # keep in sych with NFv9_REMAPPED_OUT_BYTES
      type: varint
    - name: out_packets
      index: 203 # keep in sych with NFv9_REMAPPED_OUT_PKTS
      type: varint
# Decoder mappings
netflowv9:
  mapping:
    - field: 1
      destination: in_bytes
    - field: 2
      destination: in_packets
    - field: 23
      destination: out_bytes
    - field: 24
      destination: out_packets
`

var log *logrus.Logger //nolint:unused

func SetLogger(l *logrus.Logger) {
	log = l
}

func init() {
	format.RegisterFormatDriver("ntopjson", &NtopngJson{})
	format.RegisterFormatDriver("ntoptlv", &NtopngTlv{})
}
