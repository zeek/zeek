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
    virtual bool DoInit(string path, int num_fields, LogField** fields);
    virtual bool DoWrite(int num_fields, LogField** fields, LogVal** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(string rotated_path);
	virtual bool DoFlush();
    virtual void DoFinish();

private:
	FILE* file;
	char* fname;
};

#endif
