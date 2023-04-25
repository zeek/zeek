// Analyzer for connections that transfer binary data.

#pragma once

#include <string>

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::file
	{

class File_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	File_Analyzer(const char* name, Connection* conn);

	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;

	void Undelivered(uint64_t seq, int len, bool orig) override;

	//	static analyzer::Analyzer* Instantiate(Connection* conn)
	//		{ return new File_Analyzer(conn); }

protected:
	void Identify();

	static const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE] = {0};
	int buffer_len = 0;
	std::string file_id_orig;
	std::string file_id_resp;
	};

class FTP_Data : public File_Analyzer
	{
public:
	explicit FTP_Data(Connection* conn) : File_Analyzer("FTP_Data", conn) { }

	static Analyzer* Instantiate(Connection* conn) { return new FTP_Data(conn); }
	};

	} // namespace zeek::analyzer::file
