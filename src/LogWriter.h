// See the file "COPYING" in the main distribution directory for copyright.
//
// Interface API for a log writer backend. The LogMgr creates a separate
// writer instance of pair of (writer type, output path).
//
// Note thay classes derived from LogWriter must be fully thread-safe and not
// use any non-thread-safe Bro functionality (which includes almost
// everything ...). In particular, do not use fmt() but LogWriter::Fmt()!.
//
// The one exception to this rule is the constructor: it is guaranteed to be
// executed inside the main thread and can thus in particular access global
// script variables.

#ifndef LOGWRITER_H
#define LOGWRITER_H

#include "LogMgr.h"
#include "BroString.h"

class LogWriter {
public:
	LogWriter();
	virtual ~LogWriter();

	//// Interface methods to interact with the writer. Note that these
	//// methods are not necessarily thread-safe and must be called only
	//// from the main thread (which will typically mean only from the
	//// LogMgr). In particular, they must not be called from the
	//// writer's derived implementation.

	// One-time initialization of the writer to define the logged fields.
	// Interpretation of "path" is left to the writer, and will be
	// corresponding the value configured on the script-level.
	// 
	// Returns false if an error occured, in which case the writer must
	// not be used further.
	//
	// The new instance takes ownership of "fields", and will delete them
	// when done.
	bool Init(string path, int num_fields, const LogField* const * fields);

	// Writes one log entry. The method takes ownership of "vals" and
	// will return immediately after queueing the write request, which is
	// potentially before output has actually been written out.
	//
	// num_fields and the types of the LogVals must match what was passed
	// to Init().
	//
	// Returns false if an error occured, in which case the writer must
	// not be used any further.
	bool Write(int num_fields, LogVal** vals);

	// Sets the buffering status for the writer, if the writer supports
	// that. (If not, it will be ignored).
	bool SetBuf(bool enabled);

	// Flushes any currently buffered output, if the writer supports 
	// that. (If not, it will be ignored).
	bool Flush();

	// Triggers rotation, if the writer supports that. (If not, it will
	// be ignored).
	bool Rotate(string rotated_path, double open, double close, bool terminating);

	// Finishes writing to this logger regularly. Must not be called if
	// an error has been indicated earlier. After calling this, no
	// further writing must be performed.
	void Finish();

	//// Thread-safe methods that may be called from the writer
	//// implementation.

	// The following methods return the information as passed to Init().
	const string Path() const	{ return path; }
	int NumFields() const	{ return num_fields; }
	const LogField* const * Fields() const	{ return fields; }

protected:
	// Methods for writers to override. If any of these returs false, it
	// will be assumed that a fatal error has occured that prevents the
	// writer from further operation. It will then be disabled and
	// deleted. When return false, the writer should also report the
	// error via Error(). Note that even if a writer does not support the
	// functionality for one these methods (like rotation), it must still
	// return true if that is not to be considered a fatal error.
	//
	// Called once for initialization of the writer.
	virtual bool DoInit(string path, int num_fields,
			    const LogField* const * fields) = 0;

	// Called once per log entry to record.
	virtual bool DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals) = 0;

	// Called when the buffering status for this writer is changed. If
	// buffering is disabled, the writer should attempt to write out
	// information as quickly as possible even if doing so may have a
	// performance impact. If enabled (which is the default), it may
	// buffer data as helpful and write it out later in a way optimized
	// for performance. The current buffering state can be queried via
	// IsBuf().
	//
	// A writer may ignore buffering changes if it doesn't fit with its
	// semantics (but must still return true in that case).
	virtual bool DoSetBuf(bool enabled) = 0;

	// Called to flush any currently buffered output.
	//
	// A writer may ignore flush requests if it doesn't fit with its
	// semantics (but must still return true in that case).
	virtual bool DoFlush() = 0;

	// Called when a log output is to be rotated. Most directly this only
	// applies to writers writing into files, which should then close the
	// current file and open a new one.  However, a writer may also
	// trigger other apppropiate actions if semantics are similar.
	// 
	// Once rotation has finished, the implementation should call
	// RotationDone() to signal the log manager that potential
	// postprocessors can now run.
	//
	// "rotate_path" reflects the path to where the rotated output is to
	// be moved, with specifics depending on the writer. It should
	// generally be interpreted in a way consistent with that of "path"
	// as passed into DoInit(). As an example, for file-based output, 
	// "rotate_path" could be the original filename extended with a
	// timestamp indicating the time of the rotation.
	// 
	// "open" and "close" are the network time's when the *current* file
	// was opened and closed, respectively.
	//
	// "terminating" indicated whether the rotation request occurs due
	// the main Bro prcoess terminating (and not because we've reach a
	// regularly scheduled time for rotation).
	//
	// A writer may ignore rotation requests if it doesn't fit with its
	// semantics (but must still return true in that case).
	virtual bool DoRotate(string rotated_path, double open, double close,
			      bool terminating) = 0;

	// Called once on termination. Not called when any of the other
	// methods has previously signaled an error, i.e., executing this
	// method signals a regular shutdown of the writer.
	virtual void DoFinish() = 0;

	//// Methods for writers to use. These are thread-safe.

	// A thread-safe version of fmt().
	const char* Fmt(const char* format, ...);

	// Returns the current buffering state.
	bool IsBuf()	{ return buffering; }

	// Reports an error to the user.
	void Error(const char *msg);

	// Signals to the log manager that a file has been rotated.
	//
	// new_name: The filename of the rotated file. old_name: The filename
	// of the origina file.
	//
	// open/close: The timestamps when the original file was opened and
	// closed, respectively.
	//
	// terminating: True if rotation request occured due to the main Bro
	// process shutting down.
	bool FinishedRotation(string new_name, string old_name, double open,
			      double close, bool terminating);

private:
	friend class LogMgr;

	// When an error occurs, we call this method to set a flag marking
	// the writer as disabled. The LogMgr will check the flag later and
	// remove the writer.
	bool Disabled()	{ return disabled; }

	// Deletes the values as passed into Write().
	void DeleteVals(LogVal** vals);

	string path;
	int num_fields;
	const LogField* const * fields;
	bool buffering;
	bool disabled;

	// For implementing Fmt().
	char* buf;
	unsigned int buf_len;
};

#endif
