// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

#include "IntrusivePtr.h"

class IP_Hdr;

ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);

namespace zeek {
using FuncPtr = zeek::IntrusivePtr<Func>;
}

class Discarder {
public:
	Discarder();
	~Discarder();

	bool IsActive();

	bool NextPacket(const IP_Hdr* ip, int len, int caplen);

protected:
	zeek::Val* BuildData(const u_char* data, int hdrlen, int len, int caplen);

	zeek::FuncPtr check_ip;
	zeek::FuncPtr check_tcp;
	zeek::FuncPtr check_udp;
	zeek::FuncPtr check_icmp;

	// Maximum amount of application data passed to filtering functions.
	int discarder_maxlen;
};
