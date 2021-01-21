// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <stdint.h>

extern "C" {
#include <pcap.h>
}

namespace zeek::iosource::detail {

// BPF_Programs are an abstraction around struct bpf_program,
// to create a clean facility for creating, compiling, and
// freeing such programs.

class BPF_Program {
public:
	// Creates an empty, uncompiled BPF program.
	BPF_Program();
	~BPF_Program();

	// Creates a BPF program for the given pcap handle.
	// Parameters are like in pcap_compile(). Returns true
	// for successful compilation, false otherwise.
	bool Compile(pcap_t* pcap, const char* filter, uint32_t netmask,
		 char* errbuf = nullptr, unsigned int errbuf_len = 0,
		 bool optimize = true);

	// Creates a BPF program when no pcap handle is around,
	// similarly to pcap_compile_nopcap(). Parameters are
	// similar. Returns true on success.
	bool Compile(int snaplen, int linktype, const char* filter,
		uint32_t netmask, char* errbuf = nullptr, unsigned int errbuf_len = 0,
		bool optimize = true);

	// Returns true if this program currently contains compiled
	// code, false otherwise.
	bool IsCompiled()	{ return m_compiled; }

	// Returns true if this program matches any packets. This is not
	// comprehensive, but can identify a few cases where it does.
	bool MatchesAnything() 	{ return m_matches_anything; }

	// Accessor to the compiled program. Returns nil when
	// no program is currently compiled.
	bpf_program* GetProgram();

protected:
	void FreeCode();

	// (I like to prefix member variables with m_, makes it clear
	// in the implementation whether it's a global or not. --ck)
	bool m_compiled;
	bool m_matches_anything;
	struct bpf_program m_program;
};

} // namespace zeek::iosource::detail
