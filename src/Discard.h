// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

class IP_Hdr;
class Val;
class Func;

class Discarder {
public:
	Discarder();
	~Discarder();

	bool IsActive();

	bool NextPacket(const IP_Hdr* ip, int len, int caplen);

protected:
	Val* BuildData(const u_char* data, int hdrlen, int len, int caplen);

	Func* check_ip;
	Func* check_tcp;
	Func* check_udp;
	Func* check_icmp;

	// Maximum amount of application data passed to filtering functions.
	int discarder_maxlen;
};
