// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_NTP_NTP_H
#define ANALYZER_PROTOCOL_NTP_NTP_H

#include "analyzer/protocol/udp/UDP.h"

// The following are from the tcpdump distribution, credited there
// to the U of MD implementation.

#define JAN_1970	2208988800.0	/* 1970 - 1900 in seconds */

namespace analyzer { namespace ntp {

struct l_fixedpt {
	unsigned int int_part;
	unsigned int fraction;
};

struct s_fixedpt {
	unsigned short int_part;
	unsigned short fraction;
};

struct ntpdata {
	unsigned char status;	/* status of local clock and leap info */
	unsigned char stratum;	/* Stratum level */
	unsigned char ppoll;	/* poll value */
	int precision:8;
	struct s_fixedpt distance;
	struct s_fixedpt dispersion;
	unsigned int refid;
	struct l_fixedpt reftime;
	struct l_fixedpt org;
	struct l_fixedpt rec;
	struct l_fixedpt xmt;
};

class NTP_Analyzer : public analyzer::Analyzer {
public:
	NTP_Analyzer(Connection* conn);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NTP_Analyzer(conn); }

protected:
	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	int Request(const u_char* data, int len);
	int Reply(const u_char* data, int len);

	// NTP is a unidirectional protocol, so no notion of "requests"
	// as separate from "replies".
	void Message(const u_char* data, int len);

	double ShortFloat(struct s_fixedpt fp);
	double LongFloat(struct l_fixedpt fp);
	double ConvertToDouble(unsigned int int_part, unsigned int fraction,
				double frac_base);

	friend class ConnectionTimer;
	void ExpireTimer(double t);
};

} } // namespace analyzer::* 

#endif
