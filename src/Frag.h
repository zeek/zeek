// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <tuple>

#include "zeek/util.h" // for bro_uint_t
#include "zeek/IPAddr.h"
#include "zeek/Reassem.h"
#include "zeek/Timer.h"

namespace zeek {

class SessionManager;
class IP_Hdr;

namespace detail {

class FragReassembler;
class FragTimer;

using FragReassemblerKey = std::tuple<IPAddr, IPAddr, bro_uint_t>;

class FragReassembler : public Reassembler {
public:
	FragReassembler(SessionManager* s, const std::unique_ptr<IP_Hdr>& ip, const u_char* pkt,
	                const FragReassemblerKey& k, double t);
	~FragReassembler() override;

	void AddFragment(double t, const std::unique_ptr<IP_Hdr>& ip, const u_char* pkt);

	void Expire(double t);
	void DeleteTimer();
	void ClearTimer()	{ expire_timer = nullptr; }

	std::unique_ptr<IP_Hdr> ReassembledPkt()	{ return std::move(reassembled_pkt); }
	const FragReassemblerKey& Key() const	{ return key; }

protected:
	void BlockInserted(DataBlockMap::const_iterator it) override;
	void Overlap(const u_char* b1, const u_char* b2, uint64_t n) override;
	void Weird(const char* name) const;

	u_char* proto_hdr;
	std::unique_ptr<IP_Hdr> reassembled_pkt;
	SessionManager* s;
	uint64_t frag_size;	// size of fully reassembled fragment
	FragReassemblerKey key;
	uint16_t next_proto; // first IPv6 fragment header's next proto field
	uint16_t proto_hdr_len;

	FragTimer* expire_timer;
};

class FragTimer final : public Timer {
public:
	FragTimer(FragReassembler* arg_f, double arg_t)
		: Timer(arg_t, TIMER_FRAG)
			{ f = arg_f; }
	~FragTimer() override;

	void Dispatch(double t, bool is_expire) override;

	// Break the association between this timer and its creator.
	void ClearReassembler()	{ f = nullptr; }

protected:
	FragReassembler* f;
};

class FragmentManager {
public:

	FragmentManager() = default;
	~FragmentManager();

	FragReassembler* NextFragment(double t, const std::unique_ptr<IP_Hdr>& ip,
	                              const u_char* pkt);
	void Clear();
	void Remove(detail::FragReassembler* f);

	size_t Size() const	{ return fragments.size(); }
	size_t MaxFragments() const 	{ return max_fragments; }
	uint32_t MemoryAllocation() const;

private:

	using FragmentMap = std::map<detail::FragReassemblerKey, detail::FragReassembler*>;
	FragmentMap fragments;
	size_t max_fragments = 0;
};

extern FragmentManager* fragment_mgr;

class FragReassemblerTracker {
public:
	FragReassemblerTracker(FragReassembler* f)
		: frag_reassembler(f)
		{ }

	~FragReassemblerTracker()
		{ fragment_mgr->Remove(frag_reassembler); }

private:
	FragReassembler* frag_reassembler;
};

} // namespace detail
} // namespace zeek
