#include <algorithm>

#include "File.h"

#include "file_analysis/Manager.h"
#include "RuleMatcher.h"
#include "Reporter.h"
#include "util.h"

#include "events.bif.h"

using namespace analyzer::file;

File_Analyzer::File_Analyzer(const char* name, Connection* conn)
	: TCP_ApplicationAnalyzer(name, conn)
	{
	buffer_len = 0;
	}

void File_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	int n = min(len, BUFFER_SIZE - buffer_len);

	if ( n )
		{
		strncpy(buffer + buffer_len, (const char*) data, n);
		buffer_len += n;

		if ( buffer_len == BUFFER_SIZE )
			Identify();
		}

	if ( orig )
		file_id_orig = file_mgr->DataIn(data, len, GetAnalyzerTag(), Conn(),
		                                orig, file_id_orig);
	else
		file_id_resp = file_mgr->DataIn(data, len, GetAnalyzerTag(), Conn(),
		                                orig, file_id_resp);
	}

void File_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

	if ( orig )
		file_id_orig = file_mgr->Gap(seq, len, GetAnalyzerTag(), Conn(), orig,
		                             file_id_orig);
	else
		file_id_resp = file_mgr->Gap(seq, len, GetAnalyzerTag(), Conn(), orig,
		                             file_id_resp);
	}

void File_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

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
	RuleMatcher::MIME_Matches matches;
	file_mgr->DetectMIME(reinterpret_cast<const u_char*>(buffer), buffer_len,
	                     &matches);
	string match = matches.empty() ? "<unknown>"
	                               : *(matches.begin()->second.begin());
	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(new StringVal(buffer_len, buffer));
	vl->append(new StringVal("<unknown>"));
	vl->append(new StringVal(match));
	ConnectionEvent(file_transferred, vl);
	}
