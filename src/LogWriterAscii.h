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
	FILE* file;
	string fname;
};

#endif
