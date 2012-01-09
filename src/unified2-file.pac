
enum Types {
	EVENT               = 0,
	PACKET              = 1,
	IDS_EVENT           = 2,
	IDS_EVENT_IPV6      = 72,
	IDS_EVENT_MPLS      = 99,
	IDS_EVENT_IPV6_MPLS = 100,
	IDS_EVENT_VLAN      = 104,
	IDS_EVENT_IPV6_VLAN = 105,
	EXTRA_DATA          = 110,
};


type Time = record {
	seconds:      uint32;
	microseconds: uint32;
} &byteorder=bigendian;

type v4Addr = record {
	u1: uint32;
};

type v6Addr = record {
	u1: uint32;
	u2: uint32;
	u3: uint32;
	u4: uint32;
};

type Addr(ip_ver: int) = case ip_ver of {
	4 -> v4: v4Addr;
	6 -> v6: v6Addr;
} &byteorder=bigendian;

type Record = record {
	rtype:   uint32;
	length:  uint32;
	data:   case rtype of {
		# EVENT               -> event:               Event(this);
		PACKET              -> packet:              Packet(this);
		IDS_EVENT           -> ids_event:           LegacyIDSEvent(this, 4);
		IDS_EVENT_IPV6      -> ids_event_ipv6:      LegacyIDSEvent(this, 6);
		# IDS_EVENT_MPLS      -> ids_event_mpls:      IDSEvent(this, 4);
		# IDS_EVENT_IPV6_MPLS -> ids_event_ipv6_mpls: IDSEvent(this, 6);
		IDS_EVENT_VLAN      -> ids_event_vlan:      IDSEvent(this, 4);
		IDS_EVENT_IPV6_VLAN -> ids_event_ipv6_vlan: IDSEvent(this, 6);
		EXTRA_DATA          -> extra_data:          ExtraData(this);
		default             -> unknown_record_type: UnknownRecordType(this);
	};
} &byteorder=bigendian &length=length+8;

type LegacyIDSEvent(rec: Record, ip_ver: int) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	ts:                 Time;
	signature_id:       uint32;
	generator_id:       uint32;
	signature_revision: uint32;
	classification_id:  uint32;
	priority_id:        uint32;
	src_ip:             Addr(ip_ver);
	dst_ip:             Addr(ip_ver);
	src_p:              uint16;
	dst_p:              uint16;
	protocol:           uint8;
	packet_action:      uint8;
};

type IDSEvent(rec: Record, ip_ver: int) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	ts:                 Time;
	signature_id:       uint32;
	generator_id:       uint32;
	signature_revision: uint32;
	classification_id:  uint32;
	priority_id:        uint32;
	src_ip:             Addr(ip_ver);
	dst_ip:             Addr(ip_ver);
	src_p:              uint16;
	dst_p:              uint16;
	protocol:           uint8;
	impact_flag:        uint8;
	impact:             uint8;
	blocked:            uint8;
	mpls_label:         uint32;
	vlan_id:            uint16;
	:                   uint16;
} &byteorder=bigendian;

type Packet(rec: Record) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	event_second:       uint32;
	packet_ts:          Time;
	link_type:          uint32;
	packet_len:         uint32;
	packet_data:        bytestring &length=packet_len;
} &byteorder=bigendian &length=rec.length;

type ExtraData(rec: Record) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	event_second:       uint32;
	extra_type:         uint32;
	data_type:          uint32;
	blob_len:           uint32;
	blob:               bytestring &length=blob_len;
} &byteorder=bigendian &length=rec.length;

type UnknownRecordType(rec: Record) = record {
	data: bytestring &transient &length=rec.length;
} &byteorder=bigendian &length=rec.length;

type File = record {
	alerts:  Record[] &transient &until($element <= 0);
} &byteorder=bigendian;
