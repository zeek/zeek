#include "zeek/analyzer/protocol/file/File.h"

#include <algorithm>

#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/analyzer/protocol/file/events.bif.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/util.h"

namespace zeek::analyzer::file
	{

File_Analyzer::File_Analyzer(const char* name, Connection* conn)
	: TCP_ApplicationAnalyzer(name, conn)
	{
	}

void File_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	int n = std::min(len, BUFFER_SIZE - buffer_len);

	if ( n )
		{
		memcpy(buffer + buffer_len, (const char*)data, n);
		buffer_len += n;

		if ( buffer_len == BUFFER_SIZE )
			Identify();
		}

	if ( orig )
		file_id_orig = file_mgr->DataIn(data, len, GetAnalyzerTag(), Conn(), orig, file_id_orig);
	else
		file_id_resp = file_mgr->DataIn(data, len, GetAnalyzerTag(), Conn(), orig, file_id_resp);
	}

void File_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

	if ( orig )
		file_id_orig = file_mgr->Gap(seq, len, GetAnalyzerTag(), Conn(), orig, file_id_orig);
	else
		file_id_resp = file_mgr->Gap(seq, len, GetAnalyzerTag(), Conn(), orig, file_id_resp);
	}

void File_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	if ( buffer_len && buffer_len != BUFFER_SIZE )
		Identify();

	if ( ! file_id_orig.empty() )
		file_mgr->EndOfFile(file_id_orig);
	else
		file_mgr->EndOfFile(GetAnalyzerTag(), Conn(), true);

	if ( ! file_id_resp.empty() )
		file_mgr->EndOfFile(file_id_resp);
	else
		file_mgr->EndOfFile(GetAnalyzerTag(), Conn(), false);
	}

void File_Analyzer::Identify()
	{
	detail::RuleMatcher::MIME_Matches matches;
	file_mgr->DetectMIME(reinterpret_cast<const u_char*>(buffer), buffer_len, &matches);
	std::string match = matches.empty() ? "<unknown>" : *(matches.begin()->second.begin());

	if ( file_transferred )
		EnqueueConnEvent(file_transferred, ConnVal(), make_intrusive<StringVal>(buffer_len, buffer),
		                 make_intrusive<StringVal>("<unknown>"), make_intrusive<StringVal>(match));
	}

	} // namespace zeek::analyzer::file
