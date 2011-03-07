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
    bool Init(string path, int num_fields, const LogField* const * fields);

	// Writes one log entry. The method takes ownership of "vals" and will
	// return immediately after queueing the write request, potentially
	// before the output has actually taken place. Returns false if an error
	// occured, in which case the writer must not be used further. num_fields
	// and types must match what was passed to Init().
    bool Write(int num_fields, LogVal** vals);

	// Sets the buffering status for the writer, if the writer supports it.
	bool SetBuf(bool enabled);

	// Flushes any currently buffered output, if the writer supports it.
	bool Flush();

	// Triggers rotation, if the writer supports it.
	bool Rotate(string rotated_path, string postprocessor, double open, double close, bool terminating);

	// Finished writing to this logger. Will not be called if an error has
	// been indicated earlier. After calling this, no more writing must be
	// performed.
	void Finish();

	// Returns the path as passed to Init().
	const string Path() const	{ return path; }

	int NumFields() const	{ return num_fields; }
	const LogField* const * Fields() const	{ return fields; }

protected:

 	// Methods for Writers to override. If any of these returs false, it will
 	// be assumed that a fatal error has occured that prevents the writer
 	// from further operation. It will then be disabled and deleted. In that
 	// case, the writer should also report the error via Error(). If a writer
 	// does not specifically implement one of the methods, it must still
 	// always return true.

    // Called once for initialization of the Writer.
    virtual bool DoInit(string path, int num_fields, const LogField* const * fields) = 0;

    // Called once per entry to record.
    virtual bool DoWrite(int num_fields, const LogField* const * fields, LogVal** vals) = 0;

	// Called when the buffering status for this writer is changed. If
	// buffering is disabled, the writer should attempt to write out
	// information as quickly as possible even if doing so may have an
	// performance impact. If enabled (which is the default), it can buffer
	// things up as necessary and write out in a way optimized for
	// performance. The current buffering state can be queried via IsBuf().
	//
	// A writer may ignore buffering changes if it doesn't fit with its
	// semantics.
	virtual bool DoSetBuf(bool enabled) = 0;

	// Called to flush any currently buffered output.
	//
	// A writer may ignore flush requests if it doesn't fit with its
	// semantics.
    virtual bool DoFlush() = 0;

	// Called when a log output is to be rotated. Most directly, this only
	// applies to writers outputting files, though a writer may also trigger
	// other regular actions if semantics are similar.
	//
	// The string "rotate_path" is interpreted in writer-specific way, yet
	// should generally should have similar semantics as the "path" passed
	// into DoInit(), except that now it reflects the name to where the
	// rotated output is to be moved. After rotation, output should continue
	// normally with the standard "path". As an example, for file-based
	// output, the rotate_path may be the original filename with an embedded
	// timestamp. "postprocessor" is the name of a command to execute on the
	// rotated file. If empty, no such processing should take place; if given
	// but the writer doesn't support postprocessing, it can be ignored.
	// "open" and "close" are the network time's at opening and closeing the
	// current file, respetively.
	//
	// A writer may ignore rotation requests if it doesn't fit with its
	// semantics.
	virtual bool DoRotate(string rotated_path, string postprocessor, double open, double close, bool terminating) = 0;

	// Called once on termination. Not called when any of the other methods
	// has previously signaled an error, i.e., executing this method signals
	// a regular shutdown.
    virtual void DoFinish() = 0;

    //// Methods for Writers to use. These are thread-safe.

	// A thread-safe version of fmt().
	const char* Fmt(const char* format, ...);

	// Returns the current buffering state.
	bool IsBuf()	{ return buffering; }

    // Reports an error.
    void Error(const char *msg);

	// Runs a post-processor on the given file.
	bool RunPostProcessor(string fname, string postprocessor, string old_name, double open, double close, bool terminating);

private:
	friend class LogMgr;

	// When an error occurs, we set this flag. The LogMgr will check it an
	// remove any disabled writers. 
	bool Disabled()	{ return disabled; }

    // Deletes the values passed into Write().
    void DeleteVals(LogVal** vals);

    string path;
    int num_fields;
    const LogField* const * fields;
	bool buffering;
	bool disabled;

	// For Fmt().
	char* buf;
	unsigned int buf_len;
};

#endif
