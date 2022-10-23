// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <string>

#include "zeek/util.h"

extern "C"
	{
#include <pcap.h>
	}

namespace zeek::iosource
	{

enum class FilterState : uint8_t
	{
	OK,
	FATAL, // results in Reporter::Error
	WARNING // results in Reporter::Warning
	};

namespace detail
	{

// BPF_Programs are an abstraction around struct bpf_program,
// to create a clean facility for creating, compiling, and
// freeing such programs.

class BPF_Program
	{
public:
	/**
	 * Creates an empty, uncompiled BPF program.
	 */
	BPF_Program();
	~BPF_Program();

	/**
	 * Creates a BPF program for a given pcap handle. The parameters match the usage
	 * described in the documentation for pcap_compile().
	 *
	 * @return true on successful compilation, false otherwise.
	 */
	bool Compile(pcap_t* pcap, const char* filter, uint32_t netmask, bool optimize = true);

	/**
	 * Creates a BPF program when no pcap handle is available. The parameters match the usage
	 * described in the documentation for pcap_compile_nopcap().
	 *
	 * @return true on successful compilation, false otherwise.
	 */
	bool Compile(zeek_uint_t snaplen, int linktype, const char* filter, uint32_t netmask,
	             bool optimize = true);

	/**
	 * Returns true if this program currently contains compiled code, false otherwise.
	 */
	bool IsCompiled() { return m_compiled; }

	/**
	 * Returns true if this program matches any packets. This is not comprehensive, but can
	 * identify a few cases where it does.
	 */
	bool MatchesAnything() { return m_matches_anything; }

	/**
	 * Returns the compiled program, or nullptr if no program is currently compiled.
	 */
	bpf_program* GetProgram();

	/**
	 * Returns the state of the compilation process.
	 */
	FilterState GetState() const { return state; }

	/**
	 * Returns an error message, if any, that was returned from the compilation process.
	 */
	std::string GetStateMessage() const { return state_message; }

protected:
	void FreeCode();

	FilterState GetStateFromMessage(const std::string& err);

	// (I like to prefix member variables with m_, makes it clear
	// in the implementation whether it's a global or not. --ck)
	bool m_compiled = false;
	bool m_matches_anything = false;
	struct bpf_program m_program;

	FilterState state = FilterState::OK;
	std::string state_message;
	};

	} // namespace detail
	} // namespace zeek::iosource
