
enum Types {
	PACKET           = 2,
	IDS_EVENT        = 7,
	IDS_EVENT_IPV6   = 72,
	IDS_EVENT_2      = 104,
	IDS_EVENT_IPV6_2 = 105,
	EXTRA_DATA       = 110,
};

type Time = record {
	seconds:      uint32;
	microseconds: uint32;
} &byteorder=bigendian;

type Record = record {
	rtype:   uint32;
	length:  uint32;
	data:   case rtype of {
		PACKET            -> packet:              Packet(this);
		IDS_EVENT         -> ids_event:           IDS_Event(this, 1);
		IDS_EVENT_IPV6    -> ids_event_ipv6:      IDS_Event(this, 4);
		IDS_EVENT_2       -> ids_event_vlan:      IDS_Event_2(this, 1);
		IDS_EVENT_IPV6_2  -> ids_event_ipv6_vlan: IDS_Event_2(this, 4);
		#EXTRA_DATA        -> extra_data:          ExtraData(this);
		default           -> unknown_record_type: UnknownRecordType(this);
	};
} &byteorder=bigendian &length=length+8;

type IDS_Event(rec: Record, ip_len: int) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	ts:                 Time;
	signature_id:       uint32;
	generator_id:       uint32;
	signature_revision: uint32;
	classification_id:  uint32;
	priority_id:        uint32;
	src_ip:             uint32[ip_len];
	dst_ip:             uint32[ip_len];
	src_p:              uint16;
	dst_p:              uint16;
	protocol:           uint8;
	packet_action:      uint8;
} &byteorder=bigendian;

type IDS_Event_2(rec: Record, ip_len: int) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	ts:                 Time;
	signature_id:       uint32;
	generator_id:       uint32;
	signature_revision: uint32;
	classification_id:  uint32;
	priority_id:        uint32;
	src_ip:             uint32[ip_len];
	dst_ip:             uint32[ip_len];
	src_p:              uint16;
	dst_p:              uint16;
	protocol:           uint8;
	impact_flag:        uint8;
	impact:             uint8;
	blocked:            uint8;
	mpls_label:         uint32;
	vlan_id:            uint16;
	pad:                uint16;
} &byteorder=bigendian;

type Packet(rec: Record) = record {
	sensor_id:          uint32;
	event_id:           uint32;
	event_second:       uint32;
	packet_ts:          Time;
	link_type:          uint32;
	packet_len:         uint32;
	packet_data:        bytestring &length=packet_len;
} &byteorder=bigendian;

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
