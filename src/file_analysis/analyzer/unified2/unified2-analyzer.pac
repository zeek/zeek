
%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "events.bif.h"
#include "types.bif.h"
#include "IPAddr.h"
%}

%code{
zeek::AddrValPtr binpac::Unified2::Flow::unified2_addr_to_zeek_addr(std::vector<uint32_t>* a)
	{
	if ( a->size() == 1 )
		{
		return zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv4, &(a->at(0)), zeek::IPAddr::Host));
		}
	else if ( a->size() == 4 )
		{
		uint32 tmp[4] = { a->at(0), a->at(1), a->at(2), a->at(3) };
		return zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv6, tmp, zeek::IPAddr::Host));
		}
	else
		{
		// Should never reach here.
		return zeek::make_intrusive<zeek::AddrVal>(1);
		}
	}

zeek::ValPtr binpac::Unified2::Flow::to_port(uint16_t n, uint8_t p)
	{
	TransportProto proto = TRANSPORT_UNKNOWN;
	switch ( p ) {
	case 1: proto = TRANSPORT_ICMP; break;
	case 6: proto = TRANSPORT_TCP; break;
	case 17: proto = TRANSPORT_UDP; break;
	}

	return zeek::val_mgr->Port(n, proto);
	}
%}

refine flow Flow += {

	%member{
		zeek::AddrValPtr unified2_addr_to_zeek_addr(std::vector<uint32_t>* a);
		zeek::ValPtr to_port(uint16_t n, uint8_t p);
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


	#function proc_record(rec: Record) : bool
	#	%{
	#	return true;
	#	%}

	function proc_ids_event(ev: IDS_Event) : bool
		%{
		if ( ::unified2_event )
			{
			auto ids_event = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Unified2::IDSEvent);
			ids_event->Assign(0, zeek::val_mgr->Count(${ev.sensor_id}));
			ids_event->Assign(1, zeek::val_mgr->Count(${ev.event_id}));
			ids_event->Assign(2, zeek::make_intrusive<zeek::TimeVal>(ts_to_double(${ev.ts})));
			ids_event->Assign(3, zeek::val_mgr->Count(${ev.signature_id}));
			ids_event->Assign(4, zeek::val_mgr->Count(${ev.generator_id}));
			ids_event->Assign(5, zeek::val_mgr->Count(${ev.signature_revision}));
			ids_event->Assign(6, zeek::val_mgr->Count(${ev.classification_id}));
			ids_event->Assign(7, zeek::val_mgr->Count(${ev.priority_id}));
			ids_event->Assign(8, unified2_addr_to_zeek_addr(${ev.src_ip}));
			ids_event->Assign(9, unified2_addr_to_zeek_addr(${ev.dst_ip}));
			ids_event->Assign(10, to_port(${ev.src_p}, ${ev.protocol}));
			ids_event->Assign(11, to_port(${ev.dst_p}, ${ev.protocol}));
			ids_event->Assign(17, zeek::val_mgr->Count(${ev.packet_action}));

			zeek::event_mgr.Enqueue(::unified2_event,
					connection()->zeek_analyzer()->GetFile()->ToVal(),
					std::move(ids_event));
			}
		return true;
		%}

	function proc_ids_event_2(ev: IDS_Event_2) : bool
		%{
		if ( ::unified2_event )
			{
			auto ids_event = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Unified2::IDSEvent);
			ids_event->Assign(0, zeek::val_mgr->Count(${ev.sensor_id}));
			ids_event->Assign(1, zeek::val_mgr->Count(${ev.event_id}));
			ids_event->Assign(2, zeek::make_intrusive<zeek::TimeVal>(ts_to_double(${ev.ts})));
			ids_event->Assign(3, zeek::val_mgr->Count(${ev.signature_id}));
			ids_event->Assign(4, zeek::val_mgr->Count(${ev.generator_id}));
			ids_event->Assign(5, zeek::val_mgr->Count(${ev.signature_revision}));
			ids_event->Assign(6, zeek::val_mgr->Count(${ev.classification_id}));
			ids_event->Assign(7, zeek::val_mgr->Count(${ev.priority_id}));
			ids_event->Assign(8, unified2_addr_to_zeek_addr(${ev.src_ip}));
			ids_event->Assign(9, unified2_addr_to_zeek_addr(${ev.dst_ip}));
			ids_event->Assign(10, to_port(${ev.src_p}, ${ev.protocol}));
			ids_event->Assign(11, to_port(${ev.dst_p}, ${ev.protocol}));
			ids_event->Assign(12, zeek::val_mgr->Count(${ev.impact_flag}));
			ids_event->Assign(13, zeek::val_mgr->Count(${ev.impact}));
			ids_event->Assign(14, zeek::val_mgr->Count(${ev.blocked}));
			ids_event->Assign(15, zeek::val_mgr->Count(${ev.mpls_label}));
			ids_event->Assign(16, zeek::val_mgr->Count(${ev.vlan_id}));

			zeek::event_mgr.Enqueue(::unified2_event,
					connection()->zeek_analyzer()->GetFile()->ToVal(),
					std::move(ids_event));
			}

		return true;
		%}

	function proc_packet(pkt: Packet) : bool
		%{
		if ( ::unified2_packet )
			{
			auto packet = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Unified2::Packet);
			packet->Assign(0, zeek::val_mgr->Count(${pkt.sensor_id}));
			packet->Assign(1, zeek::val_mgr->Count(${pkt.event_id}));
			packet->Assign(2, zeek::val_mgr->Count(${pkt.event_second}));
			packet->Assign(3, zeek::make_intrusive<zeek::TimeVal>(ts_to_double(${pkt.packet_ts})));
			packet->Assign(4, zeek::val_mgr->Count(${pkt.link_type}));
			packet->Assign(5, to_stringval(${pkt.packet_data}));

			zeek::event_mgr.Enqueue(::unified2_packet,
					connection()->zeek_analyzer()->GetFile()->ToVal(),
					std::move(packet));
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
