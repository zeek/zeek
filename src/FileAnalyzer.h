// Analyzer for connections that transfer binary data.

#ifndef FILEANALYZER_H
#define FILEANALYZER_H

#include "TCP.h"

#include <string>

class File_Analyzer : public TCP_ApplicationAnalyzer {
public:
	File_Analyzer(AnalyzerTag::Tag tag, Connection* conn);

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	void Undelivered(int seq, int len, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new File_Analyzer(AnalyzerTag::File, conn); }

	static bool Available()	{ return file_transferred; }

protected:
	File_Analyzer()	{}

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

	void Undelivered(int seq, int len, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new IRC_Data(conn); }

	static bool Available() { return true; }
};

class FTP_Data : public File_Analyzer {
public:

	FTP_Data(Connection* conn);

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	void Undelivered(int seq, int len, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new FTP_Data(conn); }

	static bool Available() { return true; }
};

#endif
