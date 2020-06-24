// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

#include "IntrusivePtr.h"

class IP_Hdr;
class Func;
using FuncPtr = zeek::IntrusivePtr<Func>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);

class Discarder {
public:
	Discarder();
	~Discarder();

	bool IsActive();

	bool NextPacket(const IP_Hdr* ip, int len, int caplen);

protected:
	zeek::Val* BuildData(const u_char* data, int hdrlen, int len, int caplen);

	FuncPtr check_ip;
	FuncPtr check_tcp;
	FuncPtr check_udp;
	FuncPtr check_icmp;

	// Maximum amount of application data passed to filtering functions.
	int discarder_maxlen;
};
