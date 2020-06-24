
%extern{
	#include <math.h>
	#define FRAC_16 pow(2,-16)
	#define FRAC_32 pow(2,-32)
	// NTP defines the epoch from 1900, not 1970
	#define EPOCH_OFFSET -2208988800
%}

%header{
	zeek::IntrusivePtr<Val> proc_ntp_short(const NTP_Short_Time* t);
	zeek::IntrusivePtr<Val> proc_ntp_timestamp(const NTP_Time* t);
	zeek::IntrusivePtr<RecordVal> BuildNTPStdMsg(NTP_std_msg* nsm);
	zeek::IntrusivePtr<RecordVal> BuildNTPControlMsg(NTP_control_msg* ncm);
	zeek::IntrusivePtr<RecordVal> BuildNTPMode7Msg(NTP_mode7_msg* m7);
%}


%code{
	zeek::IntrusivePtr<Val> proc_ntp_short(const NTP_Short_Time* t)
		{
		if ( t->seconds() == 0 && t->fractions() == 0 )
			return zeek::make_intrusive<IntervalVal>(0.0);
		return zeek::make_intrusive<IntervalVal>(t->seconds() + t->fractions()*FRAC_16);
		}

	zeek::IntrusivePtr<Val> proc_ntp_timestamp(const NTP_Time* t)
		{
		if ( t->seconds() == 0 && t->fractions() == 0)
			return zeek::make_intrusive<TimeVal>(0.0);
		return zeek::make_intrusive<TimeVal>(EPOCH_OFFSET + t->seconds() + t->fractions()*FRAC_32);
		}

	// This builds the standard msg record
	zeek::IntrusivePtr<RecordVal> BuildNTPStdMsg(NTP_std_msg* nsm)
		{
		auto rv = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTP::StandardMessage);

		rv->Assign(0, val_mgr->Count(${nsm.stratum}));
		rv->Assign(1, zeek::make_intrusive<IntervalVal>(pow(2, ${nsm.poll})));
		rv->Assign(2, zeek::make_intrusive<IntervalVal>(pow(2, ${nsm.precision})));
		rv->Assign(3, proc_ntp_short(${nsm.root_delay}));
		rv->Assign(4, proc_ntp_short(${nsm.root_dispersion}));

		switch ( ${nsm.stratum} ) {
		case 0:
			// unknown stratum => kiss code
			rv->Assign(5, to_stringval(${nsm.reference_id}));
			break;
		case 1:
			// reference clock => ref clock string
			rv->Assign(6, to_stringval(${nsm.reference_id}));
			break;
		default:
			{
			const uint8* d = ${nsm.reference_id}.data();
			rv->Assign(7, zeek::make_intrusive<AddrVal>(IPAddr(IPv4, (const uint32*) d, IPAddr::Network)));
			}
			break;
		}

		rv->Assign(8, proc_ntp_timestamp(${nsm.reference_ts}));
		rv->Assign(9, proc_ntp_timestamp(${nsm.origin_ts}));
		rv->Assign(10, proc_ntp_timestamp(${nsm.receive_ts}));
		rv->Assign(11, proc_ntp_timestamp(${nsm.transmit_ts}));

		if ( ${nsm.mac_len} == 20 )
			{
			rv->Assign(12, val_mgr->Count(${nsm.mac.key_id}));
			rv->Assign(13, to_stringval(${nsm.mac.digest}));
			}
		else if ( ${nsm.mac_len} == 24 )
			{
			rv->Assign(12, val_mgr->Count(${nsm.mac_ext.key_id}));
			rv->Assign(13, to_stringval(${nsm.mac_ext.digest}));
			}

		if ( ${nsm.has_exts} )
			{
			// TODO: add extension fields
			rv->Assign(14, val_mgr->Count((uint32) ${nsm.exts}->size()));
			}

		return rv;
		}

	// This builds the control msg record
	zeek::IntrusivePtr<RecordVal> BuildNTPControlMsg(NTP_control_msg* ncm)
		{
		auto rv = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTP::ControlMessage);

		rv->Assign(0, val_mgr->Count(${ncm.OpCode}));
		rv->Assign(1, val_mgr->Bool(${ncm.R}));
		rv->Assign(2, val_mgr->Bool(${ncm.E}));
		rv->Assign(3, val_mgr->Bool(${ncm.M}));
		rv->Assign(4, val_mgr->Count(${ncm.sequence}));
		rv->Assign(5, val_mgr->Count(${ncm.status}));
		rv->Assign(6, val_mgr->Count(${ncm.association_id}));

		if ( ${ncm.c} > 0 )
			rv->Assign(7, to_stringval(${ncm.data}));

		if ( ${ncm.has_control_mac} )
			{
			rv->Assign(8, val_mgr->Count(${ncm.mac.key_id}));
			rv->Assign(9, to_stringval(${ncm.mac.crypto_checksum}));
			}

		return rv;
		}

	// This builds the mode7 msg record
	zeek::IntrusivePtr<RecordVal> BuildNTPMode7Msg(NTP_mode7_msg* m7)
		{
		auto rv = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTP::Mode7Message);

		rv->Assign(0, val_mgr->Count(${m7.request_code}));
		rv->Assign(1, val_mgr->Bool(${m7.auth_bit}));
		rv->Assign(2, val_mgr->Count(${m7.sequence}));
		rv->Assign(3, val_mgr->Count(${m7.implementation}));
		rv->Assign(4, val_mgr->Count(${m7.error_code}));

		if ( ${m7.data_len} > 0 )
			rv->Assign(5, to_stringval(${m7.data}));

		return rv;
		}
%}


refine flow NTP_Flow += {


	function proc_ntp_message(msg: NTP_PDU): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( ! ntp_message )
			return false;

		auto rv = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTP::Message);
		rv->Assign(0, val_mgr->Count(${msg.version}));
		rv->Assign(1, val_mgr->Count(${msg.mode}));

		// The standard record
		if ( ${msg.mode} >=1 && ${msg.mode} <= 5 )
			rv->Assign(2, BuildNTPStdMsg(${msg.std}));
		else if ( ${msg.mode} == 6 )
			rv->Assign(3, BuildNTPControlMsg(${msg.control}));
		else if ( ${msg.mode} == 7 )
			rv->Assign(4, BuildNTPMode7Msg(${msg.mode7}));

		zeek::BifEvent::enqueue_ntp_message(connection()->bro_analyzer(),
		                              connection()->bro_analyzer()->Conn(),
		                              is_orig(), std::move(rv));
		return true;
		%}
};

refine typeattr NTP_PDU += &let {
	proc: bool = $context.flow.proc_ntp_message(this);
};
