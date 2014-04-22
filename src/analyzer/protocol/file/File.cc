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
	return;
	}

void File_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	}

void File_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( buffer_len && buffer_len != BUFFER_SIZE )
		Identify();
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

IRC_Data::IRC_Data(Connection* conn)
	: File_Analyzer("IRC_Data", conn)
	{
	}

void IRC_Data::Done()
	{
	File_Analyzer::Done();
	file_mgr->EndOfFile(GetAnalyzerTag(), Conn());
	}

void IRC_Data::DeliverStream(int len, const u_char* data, bool orig)
	{
	File_Analyzer::DeliverStream(len, data, orig);
	file_mgr->DataIn(data, len, GetAnalyzerTag(), Conn(), orig);
	}

void IRC_Data::Undelivered(int seq, int len, bool orig)
	{
	File_Analyzer::Undelivered(seq, len, orig);
	file_mgr->Gap(seq, len, GetAnalyzerTag(), Conn(), orig);
	}

FTP_Data::FTP_Data(Connection* conn)
	: File_Analyzer("FTP_Data", conn)
	{
	}

void FTP_Data::Done()
	{
	File_Analyzer::Done();
	file_mgr->EndOfFile(GetAnalyzerTag(), Conn());
	}

void FTP_Data::DeliverStream(int len, const u_char* data, bool orig)
	{
	File_Analyzer::DeliverStream(len, data, orig);
	file_mgr->DataIn(data, len, GetAnalyzerTag(), Conn(), orig);
	}

void FTP_Data::Undelivered(int seq, int len, bool orig)
	{
	File_Analyzer::Undelivered(seq, len, orig);
	file_mgr->Gap(seq, len, GetAnalyzerTag(), Conn(), orig);
	}
