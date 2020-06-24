// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

#include "IntrusivePtr.h"

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

	zeek::IntrusivePtr<Func> check_ip;
	zeek::IntrusivePtr<Func> check_tcp;
	zeek::IntrusivePtr<Func> check_udp;
	zeek::IntrusivePtr<Func> check_icmp;

	// Maximum amount of application data passed to filtering functions.
	int discarder_maxlen;
};
