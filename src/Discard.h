// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

#include "IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(IP_Hdr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);

namespace zeek {
using FuncPtr = IntrusivePtr<Func>;

namespace detail {

class Discarder {
public:
	Discarder();
	~Discarder();

	bool IsActive();

	bool NextPacket(const IP_Hdr* ip, int len, int caplen);

protected:
	Val* BuildData(const u_char* data, int hdrlen, int len, int caplen);

	FuncPtr check_ip;
	FuncPtr check_tcp;
	FuncPtr check_udp;
	FuncPtr check_icmp;

	// Maximum amount of application data passed to filtering functions.
	int discarder_maxlen;
};

} // namespace detail
} // namespace zeek
