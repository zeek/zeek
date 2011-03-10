//
// Log writer for tab-separated ASCII logs. 
//

#ifndef LOGWRITERASCII_H
#define LOGWRITERASCII_H

#include "LogWriter.h"

class LogWriterAscii : public LogWriter {
public:
	LogWriterAscii();
	~LogWriterAscii();

	static LogWriter* Instantiate()	{ return new LogWriterAscii; }

protected:
    virtual bool DoInit(string path, int num_fields, const LogField* const * fields);
    virtual bool DoWrite(int num_fields, const LogField* const * fields, LogVal** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(string rotated_path, string postprocessr, double open, double close, bool terminating);
	virtual bool DoFlush();
    virtual void DoFinish();

private:
	bool IsSpecial(string path) 	{ return path.find("/dev/") == 0; }

	FILE* file;
	string fname;

	// Options from the script-level
	bool output_to_stdout;
	bool include_header;

	char* separator;
	int separator_len;

	char* empty_field;
	int empty_field_len;

	char* unset_field;
	int unset_field_len;

	char* header_prefix;
	int header_prefix_len;
};

#endif
