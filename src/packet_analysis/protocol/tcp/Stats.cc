// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/Stats.h"

#include "zeek/File.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"

namespace zeek::packet_analysis::TCP {

TCPStateStats::TCPStateStats()
	{
	for ( int i = 0; i < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++i )
		for ( int j = 0; j < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++j )
			state_cnt[i][j] = 0;
	}

void TCPStateStats::ChangeState(analyzer::tcp::EndpointState o_prev, analyzer::tcp::EndpointState o_now,
                                analyzer::tcp::EndpointState r_prev, analyzer::tcp::EndpointState r_now)
	{
	--state_cnt[o_prev][r_prev];
	++state_cnt[o_now][r_now];
	}

void TCPStateStats::FlipState(analyzer::tcp::EndpointState orig, analyzer::tcp::EndpointState resp)
	{
	--state_cnt[orig][resp];
	++state_cnt[resp][orig];
	}

unsigned int TCPStateStats::NumStatePartial() const
	{
	unsigned int sum = 0;
	for ( int i = 0; i < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++i )
		{
		sum += state_cnt[analyzer::tcp::TCP_ENDPOINT_PARTIAL][i];
		sum += state_cnt[i][analyzer::tcp::TCP_ENDPOINT_PARTIAL];
		}

	return sum;
	}

void TCPStateStats::PrintStats(File* file, const char* prefix)
	{
	file->Write(prefix);
	file->Write("        Inact.  Syn.    SA      Part.   Est.    Fin.    Rst.\n");

	for ( int i = 0; i < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++i )
		{
		file->Write(prefix);

		switch ( i ) {
#define STATE_STRING(state, str) \
	case state: \
		file->Write(str); \
		break;

		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_INACTIVE, "Inact.");
		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_SYN_SENT, "Syn.  ");
		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT, "SA    ");
		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_PARTIAL, "Part. ");
		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED, "Est.  ");
		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_CLOSED, "Fin.  ");
		STATE_STRING(analyzer::tcp::TCP_ENDPOINT_RESET, "Rst.  ");

		}

		file->Write("  ");

		for ( int j = 0; j < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++j )
			{
			unsigned int n = state_cnt[i][j];
			if ( n > 0 )
				{
				char buf[32];
				snprintf(buf, sizeof(buf), "%-8d", state_cnt[i][j]);
				file->Write(buf);
				}
			else
				file->Write("        ");
			}

		file->Write("\n");
		}
	}

} // namespace zeek::packet_analysis::TCP
