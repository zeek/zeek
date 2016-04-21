%extern{
#include <math.h>
#define FRAC_16 pow(2,-16)
#define FRAC_32 pow(2,-32)
// NTP defines the epoch from 1900, not 1970
#define EPOCH_OFFSET -2208988800
%}

%header{
Val* proc_ntp_short(const NTP_Short_Time* t);
Val* proc_ntp_timestamp(const NTP_Time* t);
%}

%code{
Val* proc_ntp_short(const NTP_Short_Time* t)
	{
  if ( t->seconds() == 0 && t->fractions() == 0 )
    return new Val(0.0, TYPE_INTERVAL);
  return new Val(t->seconds() + t->fractions()*FRAC_16, TYPE_INTERVAL);
	}

Val* proc_ntp_timestamp(const NTP_Time* t)
 {
   if ( t->seconds() == 0 && t->fractions() == 0)
     return new Val(0.0, TYPE_TIME);
   return new Val(EPOCH_OFFSET + t->seconds() + (t->fractions()*FRAC_32), TYPE_TIME);
 }
%}

refine flow NTP_Flow += {
	function proc_ntp_message(msg: NTP_PDU): bool
		%{
    if ( ${msg.mode} == 7 )
      return true;

    RecordVal* rv = new RecordVal(BifType::Record::NTP::Message);
    rv->Assign(0, new Val(${msg.version}, TYPE_COUNT));
    rv->Assign(1, new Val(${msg.mode}, TYPE_COUNT));
    rv->Assign(2, new Val(${msg.stratum}, TYPE_COUNT));
    rv->Assign(3, new Val(pow(2, ${msg.poll}), TYPE_INTERVAL));
    rv->Assign(4, new Val(pow(2, ${msg.precision}), TYPE_INTERVAL));

    rv->Assign(5, proc_ntp_short(${msg.root_delay}));
    rv->Assign(6, proc_ntp_short(${msg.root_dispersion}));
    switch ( ${msg.stratum} )
      {
      case 0:
        // unknown stratum => kiss code
        rv->Assign(7, bytestring_to_val(${msg.reference_id}));
        break;
      case 1:
        // reference clock => ref clock string
        rv->Assign(8, bytestring_to_val(${msg.reference_id}));
        break;
      default:
        // TODO: Check for v4/v6
        const uint8* d = ${msg.reference_id}.data();
        rv->Assign(9, new AddrVal(IPAddr(IPv4, (const uint32*) d, IPAddr::Network)));
        break;
  		}

    rv->Assign(11, proc_ntp_timestamp(${msg.reference_ts}));
    rv->Assign(12, proc_ntp_timestamp(${msg.origin_ts}));
    rv->Assign(13, proc_ntp_timestamp(${msg.receive_ts}));
    rv->Assign(14, proc_ntp_timestamp(${msg.transmit_ts}));

    rv->Assign(17, new Val((uint32) ${msg.extensions}->size(), TYPE_COUNT));

		BifEvent::generate_ntp_message(connection()->bro_analyzer(),
                                   connection()->bro_analyzer()->Conn(),
                                   rv);
		return true;
		%}
};

refine typeattr NTP_PDU += &let {
	proc: bool = $context.flow.proc_ntp_message(this);
};
