// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "util.h" // for bro_uint_t
#include "IPAddr.h"
#include "Reassem.h"
#include "Timer.h"

#include <tuple>

#include <sys/types.h> // for u_char

ZEEK_FORWARD_DECLARE_NAMESPACED(NetSessions, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IP_Hdr, zeek);

class FragReassembler;
class FragTimer;

typedef void (FragReassembler::*frag_timer_func)(double t);

using FragReassemblerKey = std::tuple<zeek::IPAddr, zeek::IPAddr, bro_uint_t>;

class FragReassembler : public Reassembler {
public:
	FragReassembler(zeek::NetSessions* s, const zeek::IP_Hdr* ip, const u_char* pkt,
	                const FragReassemblerKey& k, double t);
	~FragReassembler() override;

	void AddFragment(double t, const zeek::IP_Hdr* ip, const u_char* pkt);

	void Expire(double t);
	void DeleteTimer();
	void ClearTimer()	{ expire_timer = nullptr; }

	const zeek::IP_Hdr* ReassembledPkt()	{ return reassembled_pkt; }
	const FragReassemblerKey& Key() const	{ return key; }

protected:
	void BlockInserted(DataBlockMap::const_iterator it) override;
	void Overlap(const u_char* b1, const u_char* b2, uint64_t n) override;
	void Weird(const char* name) const;

	u_char* proto_hdr;
	zeek::IP_Hdr* reassembled_pkt;
	zeek::NetSessions* s;
	uint64_t frag_size;	// size of fully reassembled fragment
	FragReassemblerKey key;
	uint16_t next_proto; // first IPv6 fragment header's next proto field
	uint16_t proto_hdr_len;

	FragTimer* expire_timer;
};

class FragTimer final : public zeek::detail::Timer {
public:
	FragTimer(FragReassembler* arg_f, double arg_t)
		: zeek::detail::Timer(arg_t, zeek::detail::TIMER_FRAG)
			{ f = arg_f; }
	~FragTimer() override;

	void Dispatch(double t, bool is_expire) override;

	// Break the association between this timer and its creator.
	void ClearReassembler()	{ f = nullptr; }

protected:
	FragReassembler* f;
};
