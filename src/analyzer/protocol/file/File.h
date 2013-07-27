// Analyzer for connections that transfer binary data.

#ifndef ANALYZER_PROTOCOL_FILE_FILE_H
#define ANALYZER_PROTOCOL_FILE_FILE_H

#include "analyzer/protocol/tcp/TCP.h"

#include <string>

namespace analyzer { namespace file {

class File_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	File_Analyzer(const char* name, Connection* conn);

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	void Undelivered(int seq, int len, bool orig);

//	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
//		{ return new File_Analyzer(conn); }

protected:
	void Identify();

	static const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	int buffer_len;
};

class IRC_Data : public File_Analyzer {
public:
	IRC_Data(Connection* conn);

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	virtual void Undelivered(int seq, int len, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new IRC_Data(conn); }
};

class FTP_Data : public File_Analyzer {
public:
	FTP_Data(Connection* conn);

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	virtual void Undelivered(int seq, int len, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new FTP_Data(conn); }
};

} } // namespace analyzer::* 

#endif
