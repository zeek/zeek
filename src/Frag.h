// See the file "COPYING" in the main distribution directory for copyright.

#ifndef frag_h
#define frag_h

#include "util.h"
#include "IP.h"
#include "Net.h"
#include "Reassem.h"
#include "Timer.h"

class HashKey;
class NetSessions;

class FragReassembler;
class FragTimer;

typedef void (FragReassembler::*frag_timer_func)(double t);

class FragReassembler : public Reassembler {
public:
	FragReassembler(NetSessions* s, const IP_Hdr* ip, const u_char* pkt,
			HashKey* k, double t);
	~FragReassembler();

	void AddFragment(double t, const IP_Hdr* ip, const u_char* pkt);

	void Expire(double t);
	void DeleteTimer();
	void ClearTimer()	{ expire_timer = 0; }

	const IP_Hdr* ReassembledPkt()	{ return reassembled_pkt; }
	HashKey* Key() const	{ return key; }

protected:
	void BlockInserted(DataBlock* start_block);
	void Overlap(const u_char* b1, const u_char* b2, int n);
	void Weird(const char* name) const;

	u_char* proto_hdr;
	IP_Hdr* reassembled_pkt;
	int proto_hdr_len;
	NetSessions* s;
	int frag_size;	// size of fully reassembled fragment
	uint16 next_proto; // first IPv6 fragment header's next proto field
	HashKey* key;

	FragTimer* expire_timer;
};

class FragTimer : public Timer {
public:
	FragTimer(FragReassembler* arg_f, double arg_t)
		: Timer(arg_t, TIMER_FRAG)
			{ f = arg_f; }
	~FragTimer();

	void Dispatch(double t, int is_expire);

	// Break the association between this timer and its creator.
	void ClearReassembler()	{ f = 0; }

protected:
	FragReassembler* f;
};

#endif
