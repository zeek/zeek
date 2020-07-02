// Analyzer for connections that transfer binary data.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

#include <string>

namespace analyzer { namespace file {

class File_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	File_Analyzer(const char* name, Connection* conn);

	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;

	void Undelivered(uint64_t seq, int len, bool orig) override;

//	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
//		{ return new File_Analyzer(conn); }

protected:
	void Identify();

	static const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	int buffer_len;
	std::string file_id_orig;
	std::string file_id_resp;
};

class IRC_Data : public File_Analyzer {
public:
	explicit IRC_Data(Connection* conn)
		: File_Analyzer("IRC_Data", conn)
		{ }

	static Analyzer* Instantiate(Connection* conn)
		{ return new IRC_Data(conn); }
};

class FTP_Data : public File_Analyzer {
public:
	explicit FTP_Data(Connection* conn)
		: File_Analyzer("FTP_Data", conn)
		{ }

	static Analyzer* Instantiate(Connection* conn)
		{ return new FTP_Data(conn); }
};

} } // namespace analyzer::*
