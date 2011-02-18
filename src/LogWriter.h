//
// Interface API for a log writer backend.
//
// Note than classes derived from LogWriter must be fully thread-safe and not
// use any non-safe Bro functionality (which is almost all ...). In
// particular, do not use fmt() but LogWriter::Fmt()!.

#ifndef LOGWRITER_H
#define LOGWRITER_H

#include "LogMgr.h"
#include "BroString.h"

class LogWriter {
public:
	LogWriter();
    virtual ~LogWriter();

	// One-time initialization of the writer, defining the logged fields.
	// Interpretation of "path" is left to the writer, and will be the value
	// configured on the script-level.  Returns false if an error occured, in
	// which case the writer must not be used futher. 
	//
    // The new instance takes ownership of "fields", and will delete them
    // when done.
    bool Init(string path, int num_fields, LogField** fields);

    // Writes one log entry. The method takes ownership of "vals" and will
    // return immediately after queueing the write request, potentially
    // before the output has actually taken place. Returns false if an error
    // occured, in which case the writer must not be used further. 
    bool Write(LogVal** vals);

	// Finished writing to this logger. Will not be called if an error has
	// been indicated earlier. After calling this, no more writing must be
	// performed.
	void Finish();

protected:

    //// Methods for Writers to override.

    // Called once for initialization of the Writer. Must return false if an
    // error occured, in which case the writer will be disabled. The error
    // reason should be reported via Error().
    virtual bool DoInit(string path, int num_fields, LogField** fields) = 0;

    // Called once per entry to record. Must return false if an error
    // occured, in which case the writer will be disabled. The error reason
    // should be reported via Error().
    virtual bool DoWrite(int num_fields, LogField** fields, LogVal** vals) = 0;

	// Called once on termination. Not called when any of the other methods
	// has previously signaled an error, i.e., executing this method signals
	// a regular shutdown.
    virtual void DoFinish() = 0;

    //// Methods for Writers to use. These are thread-safe.

	// A thread-safe version of fmt().
	const char* Fmt(const char* format, ...);

    // Reports an error.
    void Error(const char *msg);

	// Returns the path as passed to Init().
	const string Path() const	{ return path; }

private:
    // Delete values as passed into Write().
    void DeleteVals(LogVal** vals);

    string path;
    int num_fields;
    LogField** fields;

	// For Fmt().
	char* buf;
	unsigned int buf_len;
};

#endif
