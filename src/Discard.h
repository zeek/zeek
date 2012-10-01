// See the file "COPYING" in the main distribution directory for copyright.

#ifndef discard_h
#define discard_h

#include "IP.h"
#include "Func.h"

struct ip;
struct tcphdr;
struct udphdr;
struct icmp;

class Val;
class RecordType;
class Func;

class Discarder {
public:
	Discarder();
	~Discarder();

	int IsActive();

	int NextPacket(const IP_Hdr* ip, int len, int caplen);

protected:
	Val* BuildData(const u_char* data, int hdrlen, int len, int caplen);

	Func* check_ip;
	Func* check_tcp;
	Func* check_udp;
	Func* check_icmp;

	// Maximum amount of application data passed to filtering functions.
	int discarder_maxlen;
};

#endif
