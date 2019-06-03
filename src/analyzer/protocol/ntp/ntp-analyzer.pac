
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

        # This builds the standard msg record
        function BuildNTPStdMsg(nsm: NTP_std_msg): BroVal
        %{
                RecordVal* rv = new RecordVal(BifType::Record::NTP::std);

               	rv->Assign(0, new Val(${nsm.stratum}, TYPE_COUNT));
                rv->Assign(1, new Val(pow(2, ${nsm.poll}), TYPE_INTERVAL));
                rv->Assign(2, new Val(pow(2, ${nsm.precision}), TYPE_INTERVAL));
                rv->Assign(3, proc_ntp_short(${nsm.root_delay}));
                rv->Assign(4, proc_ntp_short(${nsm.root_dispersion}));

              	switch ( ${nsm.stratum} )
              	{
                 case 0:
                   	// unknown stratum => kiss code
                    	rv->Assign(7, bytestring_to_val(${nsm.reference_id}));
                    	break;
                 case 1:
                    // reference clock => ref clock string
                    rv->Assign(8, bytestring_to_val(${nsm.reference_id}));
                    break;
                 default:
                   // TODO: Check for v4/v6
                   const uint8* d = ${nsm.reference_id}.data();
                   rv->Assign(9, new AddrVal(IPAddr(IPv4, (const uint32*) d, IPAddr::Network)));
                   break;
              	}

                rv->Assign(9, proc_ntp_timestamp(${nsm.reference_ts}));
                rv->Assign(10, proc_ntp_timestamp(${nsm.origin_ts}));
                rv->Assign(11, proc_ntp_timestamp(${nsm.receive_ts}));
                rv->Assign(12, proc_ntp_timestamp(${nsm.transmit_ts}));

                rv->Assign(15, new Val((uint32) ${nsm.extensions}->size(), TYPE_COUNT));

        	return rv;
        %}

        # This builds the control msg record
        function BuildNTPControlMsg(ncm: NTP_control_msg): BroVal
        %{
                RecordVal* rv = new RecordVal(BifType::Record::NTP::control);

                rv->Assign(0, new Val(${ncm.OpCode}, TYPE_COUNT));
                rv->Assign(1, new Val(${ncm.R}, TYPE_BOOL));
                rv->Assign(2, new Val(${ncm.E}, TYPE_BOOL));
                rv->Assign(3, new Val(${ncm.M}, TYPE_BOOL));
                rv->Assign(4, new Val(${ncm.sequence}, TYPE_COUNT));
                rv->Assign(5, new Val(${ncm.status}, TYPE_COUNT));
                rv->Assign(6, new Val(${ncm.association_id}, TYPE_COUNT));
                rv->Assign(7, new Val(${ncm.offs}, TYPE_COUNT));
                rv->Assign(8, new Val(${ncm.c}, TYPE_COUNT));
                rv->Assign(9, bytestring_to_val(${ncm.data}));

                return rv;
        %}

        # This builds the mode7 msg record
        function BuildNTPMode7Msg(m7: NTP_mode7_msg): BroVal
        %{
                RecordVal* rv = new RecordVal(BifType::Record::NTP::mode7);

                rv->Assign(0, new Val(${m7.request_code}, TYPE_COUNT));
                rv->Assign(1, new Val(${m7.auth_bit}, TYPE_BOOL));
                rv->Assign(2, new Val(${m7.sequence}, TYPE_COUNT));
                rv->Assign(3, new Val(${m7.implementation}, TYPE_COUNT));
                rv->Assign(4, new Val(${m7.error_code}, TYPE_COUNT));
                rv->Assign(5, bytestring_to_val(${m7.data}));

                return rv;
        %}


	function proc_ntp_message(msg: NTP_PDU): bool
	%{
	 	
    	   RecordVal* rv = new RecordVal(BifType::Record::NTP::Message);

	   rv->Assign(0, new Val(${msg.version}, TYPE_COUNT));
	   rv->Assign(1, new Val(${msg.mode}, TYPE_COUNT));

	   // The standard record
           if ( ${msg.mode}>0 && ${msg.mode}<6 ) {
	      rv->Assign(2, BuildNTPStdMsg(${msg.std})); 
	   } else if ( ${msg.mode}==6 ) {
	      rv->Assign(3, BuildNTPControlMsg(${msg.control}));
	   } else if ( ${msg.mode}==7 ) {
              rv->Assign(4, BuildNTPMode7Msg(${msg.mode7}));
           }

	   BifEvent::generate_ntp_message(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), rv);
	   return true;
	%}
};

refine typeattr NTP_PDU += &let {
	proc: bool = $context.flow.proc_ntp_message(this);
};

