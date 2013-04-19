// Analyzer for connections that transfer binary data.

#ifndef ANALYZER_PROTOCOL_FILE_FILE_H
#define ANALYZER_PROTOCOL_FILE_FILE_H

#include "analyzer/protocol/tcp/TCP.h"

#include <magic.h>

namespace analyzer { namespace file {

class File_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	File_Analyzer(Connection* conn);

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new File_Analyzer(conn); }

protected:
	void Identify();

	static const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	int buffer_len;

	static magic_t magic;
	static magic_t magic_mime;
};

} } // namespace analyzer::* 

#endif
