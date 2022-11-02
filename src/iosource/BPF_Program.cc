// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/BPF_Program.h"

#include "zeek/zeek-config.h"

// clang-format off
// Include order is required here for a working build on Windows.
#include <unistd.h>
#include <sys/socket.h>
// clang-format on
#include <cstring>

#include "zeek/util.h"

#ifdef DONT_HAVE_LIBPCAP_PCAP_FREECODE
extern "C"
	{
#include <pcap-int.h>

	int pcap_freecode(pcap_t* unused, struct bpf_program* program)
		{
		program->bf_len = 0;

		if ( program->bf_insns )
			{
			free((char*)program->bf_insns); // copied from libpcap
			program->bf_insns = 0;
			}

		return 0;
		}

	pcap_t* pcap_open_dead(int linktype, int snaplen)
		{
		pcap_t* p;

		p = (pcap_t*)malloc(sizeof(*p));
		if ( ! p )
			return 0;

		memset(p, 0, sizeof(*p));

		p->fd = -1;
		p->snapshot = snaplen;
		p->linktype = linktype;

		return p;
		}

	int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, struct bpf_program* program,
	                        char* buf, int optimize, bpf_u_int32 mask)
		{
		pcap_t* p;
		int ret;

		p = pcap_open_dead(linktype_arg, snaplen_arg);
		if ( ! p )
			return -1;

		ret = pcap_compile(p, program, buf, optimize, mask);
		pcap_close(p);

		return ret;
		}
	}
#endif

namespace zeek::iosource::detail
	{

// Simple heuristic to identify filters that always match, so that we can
// skip the filtering in that case. "ip or not ip" is Zeek's default filter.
static bool filter_matches_anything(const char* filter)
	{
	return (! filter) || strlen(filter) == 0 || strcmp(filter, "ip or not ip") == 0;
	}

BPF_Program::BPF_Program() : m_program() { }

BPF_Program::~BPF_Program()
	{
	FreeCode();
	}

bool BPF_Program::Compile(pcap_t* pcap, const char* filter, uint32_t netmask, bool optimize)
	{
	if ( ! pcap )
		return false;

	FreeCode();

	if ( pcap_compile(pcap, &m_program, (char*)filter, optimize, netmask) < 0 )
		{
		state_message = std::string(pcap_geterr(pcap));
		state = GetStateFromMessage(state_message);
		return false;
		}

	m_compiled = true;
	m_matches_anything = filter_matches_anything(filter);

	return true;
	}

bool BPF_Program::Compile(zeek_uint_t snaplen, int linktype, const char* filter, uint32_t netmask,
                          bool optimize)
	{
	FreeCode();

	if ( linktype == DLT_NFLOG )
		{
		// No-op, NFLOG does not support BPF filters.
		// Raising a warning might be good, but it would also be noisy
		// since the default scripts will always attempt to compile
		// and install a default filter
		m_compiled = true;
		m_matches_anything = true;
		return true;
		}

	pcap_t* pcap = pcap_open_dead(linktype, snaplen);
	if ( ! pcap )
		{
		state = FilterState::FATAL;
		state_message = "Failed to open pcap based on linktype/snaplen";
		return false;
		}

	bool status = Compile(pcap, filter, netmask, optimize);
	pcap_close(pcap);

	return status;
	}

bpf_program* BPF_Program::GetProgram()
	{
	return m_compiled ? &m_program : nullptr;
	}

void BPF_Program::FreeCode()
	{
	if ( m_compiled )
		{
#ifdef DONT_HAVE_LIBPCAP_PCAP_FREECODE
		pcap_freecode(NULL, &m_program);
#else
		pcap_freecode(&m_program);
#endif
		m_compiled = false;
		}
	}

FilterState BPF_Program::GetStateFromMessage(const std::string& err)
	{
	if ( err.find("filtering not implemented") != std::string::npos )
		return FilterState::WARNING;

	return FilterState::FATAL;
	}

	} // namespace zeek::iosource::detail
