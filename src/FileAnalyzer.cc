#include <algorithm>

#include "file_analysis/Manager.h"
#include "FileAnalyzer.h"
#include "Reporter.h"
#include "util.h"

magic_t File_Analyzer::magic = 0;
magic_t File_Analyzer::magic_mime = 0;

File_Analyzer::File_Analyzer(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::File, conn)
	{
	buffer_len = 0;

	bro_init_magic(&magic, MAGIC_NONE);
	bro_init_magic(&magic_mime, MAGIC_MIME);
	}

void File_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	file_mgr->DataIn(data, len, Conn(), orig);

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

	file_mgr->Gap(seq, len, Conn(), orig);
	}

void File_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	file_mgr->EndOfFile(Conn());

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
