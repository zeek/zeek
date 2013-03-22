#include <algorithm>

#include "file_analysis/Manager.h"
#include "FileAnalyzer.h"
#include "Reporter.h"
#include "util.h"

magic_t File_Analyzer::magic = 0;
magic_t File_Analyzer::magic_mime = 0;

File_Analyzer::File_Analyzer(AnalyzerTag::Tag tag, Connection* conn)
: TCP_ApplicationAnalyzer(tag, conn)
	{
	buffer_len = 0;

	bro_init_magic(&magic, MAGIC_NONE);
	bro_init_magic(&magic_mime, MAGIC_MIME);
	}

void File_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

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
	TCP_ApplicationAnalyzer::Done();

	if ( buffer_len && buffer_len != BUFFER_SIZE )
		Identify();
	}

void File_Analyzer::Identify()
	{
	const char* descr = 0;
	const char* mime = 0;

	if ( magic )
		descr = bro_magic_buffer(magic, buffer, buffer_len);

	if ( magic_mime )
		mime = bro_magic_buffer(magic_mime, buffer, buffer_len);

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(new StringVal(buffer_len, buffer));
	vl->append(new StringVal(descr ? descr : "<unknown>"));
	vl->append(new StringVal(mime ? mime : "<unknown>"));
	ConnectionEvent(file_transferred, vl);
	}

IRC_Data::IRC_Data(Connection* conn)
	: File_Analyzer(AnalyzerTag::IRC_Data, conn)
	{
	}

void IRC_Data::Done()
	{
	File_Analyzer::Done();
	file_mgr->EndOfFile(Conn());
	}

void IRC_Data::DeliverStream(int len, const u_char* data, bool orig)
	{
	File_Analyzer::DeliverStream(len, data, orig);
	file_mgr->DataIn(data, len, GetTag(), Conn(), orig);
	}

void IRC_Data::Undelivered(int seq, int len, bool orig)
	{
	File_Analyzer::Undelivered(seq, len, orig);
	file_mgr->Gap(seq, len, GetTag(), Conn(), orig);
	}

FTP_Data::FTP_Data(Connection* conn)
	: File_Analyzer(AnalyzerTag::FTP_Data, conn)
	{
	}

void FTP_Data::Done()
	{
	File_Analyzer::Done();
	file_mgr->EndOfFile(Conn());
	}

void FTP_Data::DeliverStream(int len, const u_char* data, bool orig)
	{
	File_Analyzer::DeliverStream(len, data, orig);
	file_mgr->DataIn(data, len, GetTag(), Conn(), orig);
	}

void FTP_Data::Undelivered(int seq, int len, bool orig)
	{
	File_Analyzer::Undelivered(seq, len, orig);
	file_mgr->Gap(seq, len, GetTag(), Conn(), orig);
	}
