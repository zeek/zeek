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

	int NextPacket(const IP_Hdr* ip, uint64_t len, uint64_t caplen);

protected:
	Val* BuildData(const u_char* data, uint64_t hdrlen, uint64_t len, uint64_t caplen);

	Func* check_ip;
	Func* check_tcp;
	Func* check_udp;
	Func* check_icmp;

	// Maximum amount of application data passed to filtering functions.
	uint64_t discarder_maxlen;
};

#endif
