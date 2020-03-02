
%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "events.bif.h"
#include "types.bif.h"
#include "IPAddr.h"
%}

refine flow Flow += {

	%member{
	%}

	%init{
	%}

	%eof{
	%}

	%cleanup{
	%}

	function ts_to_double(ts: Time): double
		%{
		double t = ${ts.seconds} + (${ts.microseconds} / 1000000);
		return t;
		%}

	function unified2_addr_to_bro_addr(a: uint32[]): AddrVal
		%{
		if ( a->size() == 1 )
			{
			return new AddrVal(IPAddr(IPv4, &(a->at(0)), IPAddr::Host));
			}
		else if ( a->size() == 4 )
			{
			uint32 tmp[4] = { a->at(0), a->at(1), a->at(2), a->at(3) };
			return new AddrVal(IPAddr(IPv6, tmp, IPAddr::Host));
			}
		else
			{
			// Should never reach here.
			return new AddrVal(1);
			}
		%}

	function to_port(n: uint16, p: uint8): PortVal
		%{
		TransportProto proto = TRANSPORT_UNKNOWN;
		switch ( p ) {
		case 1: proto = TRANSPORT_ICMP; break;
		case 6: proto = TRANSPORT_TCP; break;
		case 17: proto = TRANSPORT_UDP; break;
		}

		return val_mgr->GetPort(n, proto);
		%}

	#function proc_record(rec: Record) : bool
	#	%{
	#	return true;
	#	%}

	function proc_ids_event(ev: IDS_Event) : bool
		%{
		if ( ::unified2_event )
			{
			RecordVal* ids_event = new RecordVal(BifType::Record::Unified2::IDSEvent);
			ids_event->Assign(0, val_mgr->GetCount(${ev.sensor_id}));
			ids_event->Assign(1, val_mgr->GetCount(${ev.event_id}));
			ids_event->Assign(2, make_intrusive<Val>(ts_to_double(${ev.ts}), TYPE_TIME));
			ids_event->Assign(3, val_mgr->GetCount(${ev.signature_id}));
			ids_event->Assign(4, val_mgr->GetCount(${ev.generator_id}));
			ids_event->Assign(5, val_mgr->GetCount(${ev.signature_revision}));
			ids_event->Assign(6, val_mgr->GetCount(${ev.classification_id}));
			ids_event->Assign(7, val_mgr->GetCount(${ev.priority_id}));
			ids_event->Assign(8, unified2_addr_to_bro_addr(${ev.src_ip}));
			ids_event->Assign(9, unified2_addr_to_bro_addr(${ev.dst_ip}));
			ids_event->Assign(10, to_port(${ev.src_p}, ${ev.protocol}));
			ids_event->Assign(11, to_port(${ev.dst_p}, ${ev.protocol}));
			ids_event->Assign(17, val_mgr->GetCount(${ev.packet_action}));

			mgr.QueueEventFast(::unified2_event, {
					connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
					ids_event,
					},
				SOURCE_LOCAL);
			}
		return true;
		%}

	function proc_ids_event_2(ev: IDS_Event_2) : bool
		%{
		if ( ::unified2_event )
			{
			RecordVal* ids_event = new RecordVal(BifType::Record::Unified2::IDSEvent);
			ids_event->Assign(0, val_mgr->GetCount(${ev.sensor_id}));
			ids_event->Assign(1, val_mgr->GetCount(${ev.event_id}));
			ids_event->Assign(2, make_intrusive<Val>(ts_to_double(${ev.ts}), TYPE_TIME));
			ids_event->Assign(3, val_mgr->GetCount(${ev.signature_id}));
			ids_event->Assign(4, val_mgr->GetCount(${ev.generator_id}));
			ids_event->Assign(5, val_mgr->GetCount(${ev.signature_revision}));
			ids_event->Assign(6, val_mgr->GetCount(${ev.classification_id}));
			ids_event->Assign(7, val_mgr->GetCount(${ev.priority_id}));
			ids_event->Assign(8, unified2_addr_to_bro_addr(${ev.src_ip}));
			ids_event->Assign(9, unified2_addr_to_bro_addr(${ev.dst_ip}));
			ids_event->Assign(10, to_port(${ev.src_p}, ${ev.protocol}));
			ids_event->Assign(11, to_port(${ev.dst_p}, ${ev.protocol}));
			ids_event->Assign(12, val_mgr->GetCount(${ev.impact_flag}));
			ids_event->Assign(13, val_mgr->GetCount(${ev.impact}));
			ids_event->Assign(14, val_mgr->GetCount(${ev.blocked}));
			ids_event->Assign(15, val_mgr->GetCount(${ev.mpls_label}));
			ids_event->Assign(16, val_mgr->GetCount(${ev.vlan_id}));

			mgr.QueueEventFast(::unified2_event, {
					connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
					ids_event,
					},
				SOURCE_LOCAL);
			}

		return true;
		%}

	function proc_packet(pkt: Packet) : bool
		%{
		if ( ::unified2_packet )
			{
			RecordVal* packet = new RecordVal(BifType::Record::Unified2::Packet);
			packet->Assign(0, val_mgr->GetCount(${pkt.sensor_id}));
			packet->Assign(1, val_mgr->GetCount(${pkt.event_id}));
			packet->Assign(2, val_mgr->GetCount(${pkt.event_second}));
			packet->Assign(3, make_intrusive<Val>(ts_to_double(${pkt.packet_ts}), TYPE_TIME));
			packet->Assign(4, val_mgr->GetCount(${pkt.link_type}));
			packet->Assign(5, bytestring_to_val(${pkt.packet_data}));

			mgr.QueueEventFast(::unified2_packet, {
					connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
					packet,
					},
				SOURCE_LOCAL);
			}

		return true;
		%}

	#function proc_unknown_record_type(rec: UnknownRecordType) : bool
	#	%{
	#	printf("unknown packet type\n");
	#	return true;
	#	%}
};

#refine typeattr Record += &let {
#	proc : bool = $context.flow.proc_record(this);
#};

refine typeattr IDS_Event += &let {
	proc : bool = $context.flow.proc_ids_event(this);
};

refine typeattr IDS_Event_2 += &let {
	proc : bool = $context.flow.proc_ids_event_2(this);
};

refine typeattr Packet += &let {
	proc : bool = $context.flow.proc_packet(this);
};

#refine typeattr UnknownRecordType += &let {
#	proc : bool = $context.flow.proc_unknown_record_type(this);
#};
