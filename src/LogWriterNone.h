// See the file "COPYING" in the main distribution directory for copyright.
//
// Dummy log writer that just discards everything (but still pretends to rotate).

#ifndef LOGWRITERNONE_H
#define LOGWRITERNONE_H

#include "LogWriter.h"

class LogWriterNone : public LogWriter {
public:
	LogWriterNone()	{}
	~LogWriterNone()	{};

	static LogWriter* Instantiate()	{ return new LogWriterNone; }

protected:
	virtual bool DoInit(string path, int num_fields,
			    const LogField* const * fields)	{ return true; }

	virtual bool DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals)	{ return true; }
	virtual bool DoSetBuf(bool enabled)	{ return true; }
	virtual bool DoRotate(string rotated_path, double open, double close,
			      bool terminating);
	virtual bool DoFlush()	{ return true; }
	virtual void DoFinish()	{}
};

#endif
