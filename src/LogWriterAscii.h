// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for delimiter-separated ASCII logs.

#ifndef LOGWRITERASCII_H
#define LOGWRITERASCII_H

#include "LogWriter.h"

class LogWriterAscii : public LogWriter {
public:
	LogWriterAscii(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue);
	~LogWriterAscii();

	static LogWriter* Instantiate(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue);	
	static string LogExt();

protected:
	virtual bool DoInit(string path, int num_fields,
			    const LogField* const * fields);
	virtual bool DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(string rotated_path, double open, double close,
			      bool terminating);
	virtual bool DoFlush();
	virtual void DoFinish();

private:
	bool IsSpecial(string path) 	{ return path.find("/dev/") == 0; }
	bool DoWriteOne(ODesc* desc, LogVal* val, const LogField* field);
	bool WriteHeaderField(const string& key, const string& value);

	FILE* file;
	string fname;
	ODesc desc;

	// Options set from the script-level.
	bool output_to_stdout;
	bool include_header;

	char* separator;
	int separator_len;

	char* set_separator;
	int set_separator_len;

	char* empty_field;
	int empty_field_len;

	char* unset_field;
	int unset_field_len;

	char* header_prefix;
	int header_prefix_len;
};

#endif
