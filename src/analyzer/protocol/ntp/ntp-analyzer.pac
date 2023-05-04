
%extern{
	#include <cmath>
	#define FRAC_16 pow(2,-16)
	#define FRAC_32 pow(2,-32)
	// NTP defines the epoch from 1900, not 1970
	#define EPOCH_OFFSET -2208988800
%}

%header{
	zeek::ValPtr proc_ntp_short(const NTP_Short_Time* t);
	zeek::ValPtr proc_ntp_timestamp(const NTP_Time* t);
	zeek::RecordValPtr BuildNTPStdMsg(NTP_std_msg* nsm);
	zeek::RecordValPtr BuildNTPControlMsg(NTP_control_msg* ncm);
	zeek::RecordValPtr BuildNTPMode7Msg(NTP_mode7_msg* m7);
%}


%code{
	zeek::ValPtr proc_ntp_short(const NTP_Short_Time* t)
		{
		if ( t->seconds() == 0 && t->fractions() == 0 )
			return zeek::make_intrusive<zeek::IntervalVal>(0.0);
		return zeek::make_intrusive<zeek::IntervalVal>(t->seconds() + t->fractions()*FRAC_16);
		}

	zeek::ValPtr proc_ntp_timestamp(const NTP_Time* t)
		{
		if ( t->seconds() == 0 && t->fractions() == 0)
			return zeek::make_intrusive<zeek::TimeVal>(0.0);
		return zeek::make_intrusive<zeek::TimeVal>(EPOCH_OFFSET + t->seconds() + t->fractions()*FRAC_32);
		}

	// This builds the standard msg record
	zeek::RecordValPtr BuildNTPStdMsg(NTP_std_msg* nsm)
		{
		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::NTP::StandardMessage);

		rv->Assign(0, ${nsm.stratum});
		rv->AssignInterval(1, pow(2, ${nsm.poll}));
		rv->AssignInterval(2, pow(2, ${nsm.precision}));
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
			rv->Assign(7, zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv4, (const uint32*) d, zeek::IPAddr::Network)));
			}
			break;
		}

		rv->Assign(8, proc_ntp_timestamp(${nsm.reference_ts}));
		rv->Assign(9, proc_ntp_timestamp(${nsm.origin_ts}));
		rv->Assign(10, proc_ntp_timestamp(${nsm.receive_ts}));
		rv->Assign(11, proc_ntp_timestamp(${nsm.transmit_ts}));

		if ( ${nsm.mac_len} == 20 )
			{
			rv->Assign(12, ${nsm.mac.key_id});
			rv->Assign(13, to_stringval(${nsm.mac.digest}));
			}
		else if ( ${nsm.mac_len} == 24 )
			{
			rv->Assign(12, ${nsm.mac_ext.key_id});
			rv->Assign(13, to_stringval(${nsm.mac_ext.digest}));
			}

		if ( ${nsm.has_exts} )
			{
			// TODO: add extension fields
			rv->Assign(14, static_cast<uint32>(${nsm.exts}->size()));
			}

		return rv;
		}

	// This builds the control msg record
	zeek::RecordValPtr BuildNTPControlMsg(NTP_control_msg* ncm)
		{
		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::NTP::ControlMessage);

		rv->Assign(0, ${ncm.OpCode});
		rv->Assign(1, ${ncm.R});
		rv->Assign(2, ${ncm.E});
		rv->Assign(3, ${ncm.M});
		rv->Assign(4, ${ncm.sequence});
		rv->Assign(5, ${ncm.status});
		rv->Assign(6, ${ncm.association_id});

		if ( ${ncm.c} > 0 )
			rv->Assign(7, to_stringval(${ncm.data}));

		if ( ${ncm.has_control_mac} )
			{
			rv->Assign(8, ${ncm.mac.key_id});
			rv->Assign(9, to_stringval(${ncm.mac.crypto_checksum}));
			}

		return rv;
		}

	// This builds the mode7 msg record
	zeek::RecordValPtr BuildNTPMode7Msg(NTP_mode7_msg* m7)
		{
		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::NTP::Mode7Message);

		rv->Assign(0, ${m7.request_code});
		rv->Assign(1, ${m7.auth_bit});
		rv->Assign(2, ${m7.sequence});
		rv->Assign(3, ${m7.implementation});
		rv->Assign(4, ${m7.error_code});

		if ( ${m7.data_len} > 0 )
			rv->Assign(5, to_stringval(${m7.data}));

		return rv;
		}
%}


refine flow NTP_Flow += {

	%member{
		bool flipped_;
	%}

	%init{
		flipped_ = false;
	%}

	function proc_ntp_message(msg: NTP_PDU): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		// Flip roles for SERVER mode message from orig or a CLIENT mode message from resp.
		if ( ((${msg.mode} == SERVER && is_orig()) || (${msg.mode} == CLIENT && ! is_orig())) && ! flipped_ )
			{
			connection()->zeek_analyzer()->Conn()->FlipRoles();
			flipped_ = true;
			}

		if ( ! ntp_message )
			return false;

		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::NTP::Message);
		rv->Assign(0, ${msg.version});
		rv->Assign(1, ${msg.mode});

		// The standard record
		if ( ${msg.mode} >=1 && ${msg.mode} <= 5 )
			rv->Assign(2, BuildNTPStdMsg(${msg.std}));
		else if ( ${msg.mode} == 6 )
			rv->Assign(3, BuildNTPControlMsg(${msg.control}));
		else if ( ${msg.mode} == 7 )
			rv->Assign(4, BuildNTPMode7Msg(${msg.mode7}));

		zeek::BifEvent::enqueue_ntp_message(connection()->zeek_analyzer(),
		                              connection()->zeek_analyzer()->Conn(),
		                              is_orig(), std::move(rv));
		return true;
		%}
};

refine typeattr NTP_PDU += &let {
	proc: bool = $context.flow.proc_ntp_message(this);
};
