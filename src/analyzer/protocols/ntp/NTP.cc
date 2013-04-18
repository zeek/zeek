// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "NetVar.h"
#include "NTP.h"
#include "Sessions.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::ntp;

NTP_Analyzer::NTP_Analyzer(Connection* conn)
	: Analyzer("NTP", conn)
	{
	ADD_ANALYZER_TIMER(&NTP_Analyzer::ExpireTimer,
				network_time + ntp_session_timeout, 1,
				TIMER_NTP_EXPIRE);
	}

void NTP_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void NTP_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	// Actually we could just get rid of the Request/Reply and simply use
	// the code of Message().  But for now we use it as an example of how
	// to convert an old-style UDP analyzer.
	if ( is_orig )
		Request(data, len);
	else
		Reply(data, len);
	}

int NTP_Analyzer::Request(const u_char* data, int len)
	{
	Message(data, len);
	return 1;
	}

int NTP_Analyzer::Reply(const u_char* data, int len)
	{
	Message(data, len);
	return 1;
	}

void NTP_Analyzer::Message(const u_char* data, int len)
	{
	if ( (unsigned) len < sizeof(struct ntpdata) )
		{
		Weird("truncated_NTP");
		return;
		}

	struct ntpdata* ntp_data = (struct ntpdata *) data;
	len -= sizeof *ntp_data;
	data += sizeof *ntp_data;

	RecordVal* msg = new RecordVal(ntp_msg);

	unsigned int code = ntp_data->status & 0x7;

	msg->Assign(0, new Val((unsigned int) (ntohl(ntp_data->refid)), TYPE_COUNT));
	msg->Assign(1, new Val(code, TYPE_COUNT));
	msg->Assign(2, new Val((unsigned int) ntp_data->stratum, TYPE_COUNT));
	msg->Assign(3, new Val((unsigned int) ntp_data->ppoll, TYPE_COUNT));
	msg->Assign(4, new Val((unsigned int) ntp_data->precision, TYPE_INT));
	msg->Assign(5, new Val(ShortFloat(ntp_data->distance), TYPE_INTERVAL));
	msg->Assign(6, new Val(ShortFloat(ntp_data->dispersion), TYPE_INTERVAL));
	msg->Assign(7, new Val(LongFloat(ntp_data->reftime), TYPE_TIME));
	msg->Assign(8, new Val(LongFloat(ntp_data->org), TYPE_TIME));
	msg->Assign(9, new Val(LongFloat(ntp_data->rec), TYPE_TIME));
	msg->Assign(10, new Val(LongFloat(ntp_data->xmt), TYPE_TIME));

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(msg);
	vl->append(new StringVal(new BroString(data, len, 0)));

	ConnectionEvent(ntp_message, vl);
	}

double NTP_Analyzer::ShortFloat(struct s_fixedpt fp)
	{
	return ConvertToDouble(ntohs(fp.int_part), ntohs(fp.fraction), 65536.0);
	}

double NTP_Analyzer::LongFloat(struct l_fixedpt fp)
	{
	double t = ConvertToDouble(ntohl(fp.int_part), ntohl(fp.fraction),
				   4294967296.0);

	return t ? t - JAN_1970 : 0.0;
	}

double NTP_Analyzer::ConvertToDouble(unsigned int int_part,
				    unsigned int fraction, double frac_base)
	{
	return double(int_part) + double(fraction) / frac_base;
	}

void NTP_Analyzer::ExpireTimer(double /* t */)
	{
	Event(connection_timeout);
	sessions->Remove(Conn());
	}
