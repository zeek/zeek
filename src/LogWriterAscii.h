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
    bool DoInit(string path, int num_fields, LogField** fields);
    bool DoWrite(int num_fields, LogField** fields, LogVal** vals);
    void DoFinish();

private:
	FILE* file;
	char* fname;
};

#endif
