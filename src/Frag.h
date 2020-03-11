// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "util.h" // for bro_uint_t
#include "IPAddr.h"
#include "Reassem.h"
#include "Timer.h"

#include <tuple>

#include <sys/types.h> // for u_char

class HashKey;
class NetSessions;
class IP_Hdr;

class FragReassembler;
class FragTimer;

typedef void (FragReassembler::*frag_timer_func)(double t);

using FragReassemblerKey = std::tuple<IPAddr, IPAddr, bro_uint_t>;

class FragReassembler : public Reassembler {
public:
	FragReassembler(NetSessions* s, const IP_Hdr* ip, const u_char* pkt,
			const FragReassemblerKey& k, double t);
	~FragReassembler() override;

	void AddFragment(double t, const IP_Hdr* ip, const u_char* pkt);

	void Expire(double t);
	void DeleteTimer();
	void ClearTimer()	{ expire_timer = 0; }

	const IP_Hdr* ReassembledPkt()	{ return reassembled_pkt; }
	const FragReassemblerKey& Key() const	{ return key; }

protected:
	void BlockInserted(DataBlockMap::const_iterator it) override;
	void Overlap(const u_char* b1, const u_char* b2, uint64_t n) override;
	void Weird(const char* name) const;

	u_char* proto_hdr;
	IP_Hdr* reassembled_pkt;
	uint16_t proto_hdr_len;
	NetSessions* s;
	uint64_t frag_size;	// size of fully reassembled fragment
	uint16_t next_proto; // first IPv6 fragment header's next proto field
	FragReassemblerKey key;

	FragTimer* expire_timer;
};

class FragTimer : public Timer {
public:
	FragTimer(FragReassembler* arg_f, double arg_t)
		: Timer(arg_t, TIMER_FRAG)
			{ f = arg_f; }
	~FragTimer() override;

	void Dispatch(double t, bool is_expire) override;

	// Break the association between this timer and its creator.
	void ClearReassembler()	{ f = 0; }

protected:
	FragReassembler* f;
};
