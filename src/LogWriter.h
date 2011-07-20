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

#include <string>
#include <map>

#include "net_util.h"

#include "ThreadSafeQueue.h"
#include "BasicThread.h"
#include "LogBase.h"

class LogWriter;
class BulkWriteMessage;

/**
 *  Acts as a go-between for Bro / an individual logger.  Individual functions, when called, build appropriate
 *  messages and send them to whichever writer is bound to this individual LogEmissary via the pull_queue
 *  / push_queue channels.
 *
 *  Note that, in the case of IPC, there may not be a bound writer, only a bound push / pull queue.
 */

class LogEmissary {
public:
	std::string Path() const { return path; }
	const LogField* const *Fields() const { return fields; }
	const int NumFields() const { return num_fields; }

	LogEmissary(QueueInterface<MessageEvent *>& push_queue, QueueInterface<MessageEvent *>& pull_queue);
	virtual ~LogEmissary();

	/**
	 *  Note that these values are used by the child thread.  As such, once initially set,
	 *  they MUST not change!
	 */
	bool Init(const string path, const int num_fields, LogField* const *fields);
	bool Write(const int num_fields, LogVal **vals);
	bool SetBuf(const bool enabled);
	bool Flush();
	bool Rotate(string rotated_path, string postprocessor, double open,
		    double close, bool terminating);
	void Finish();
	void BindWriter(LogWriter *writer);
	LogEmissary& operator=(const LogEmissary& target);
private:
	static const size_t LOG_QUEUE_SZ = 128;                 // Must queue LOG_QUEUE_SZ messages before passing a bulk log update

	LogWriter *bound;               						// The writer we're bound to
	QueueInterface<MessageEvent *>& push_queue;     		// Pushes messages to the thread
	QueueInterface<MessageEvent *>& pull_queue;     		// Pulls notifications from the thread

	std::string path;
	LogField* const *fields;
	int num_fields;
	BulkWriteMessage *bMessage;                             // Aggregate individual log write messages until there's a timeout or we exceed the LOG_QUEUE_SZ threshold
};

class LogWriter : public BasicThread {
public:
	LogWriter(LogEmissary& parent, QueueInterface<MessageEvent *>& in_q, QueueInterface<MessageEvent *>& out_q)
	: BasicThread(in_q, out_q), parent(parent), buffered(false) { }
	
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
	// "rotate_path" reflects the path to where the rotated output is to
	// be moved, with specifics depending on the writer. It should
	// generally be interpreted in a way consistent with that of "path"
	// as passed into DoInit(). As an example, for file-based output, 
	// "rotate_path" could be the original filename extended with a
	// timestamp indicating the time of the rotation.

	// "postprocessor" is the name of a command to execute on the rotated
	// file. If empty, no postprocessing should take place; if given but
	// the writer doesn't support postprocessing, it can be ignored (but
	// the method must still return true in that case).

	// "open" and "close" are the network time's when the *current* file
	// was opened and closed, respectively.
	//
	// "terminating" indicated whether the rotation request occurs due
	// the main Bro prcoess terminating (and not because we've reach a
	// regularly scheduled time for rotation).
	//
	// A writer may ignore rotation requests if it doesn't fit with its
	// semantics (but must still return true in that case).
	virtual bool DoRotate(string rotated_path, string postprocessor,
			      double open, double close, bool terminating) = 0;

	// Called once on termination. Not called when any of the other
	// methods has previously signaled an error, i.e., executing this
	// method signals a regular shutdown of the writer.
	virtual void DoFinish() = 0;

	/**
	 *  Version of format that uses storage local to this particular LogWriter.  Given the
	 *  current threading model, this should be thread-safe.
	 */
	const char *Fmt (char * format, ...) const;

	/**
	 *  Instantiates and passes an ErrorMessage to the parent.
	 */
	void Error(const char *msg);

	bool IsBuf() { return buffered; }

	void DeleteVals(LogVal** vals, const int num_fields);

	LogWriter& operator=(const LogWriter& target);
protected:
	bool RunPostProcessor(std::string fname, std::string postprocessor,
				 std::string old_name, double open, double close,
				 bool terminating);

	LogEmissary& parent;
	bool buffered;
	const static int LOGWRITER_MAX_BUFSZ = 2048;
	mutable char strbuf[LOGWRITER_MAX_BUFSZ];
};

class RotateMessage : public MessageEvent
{
public:
	RotateMessage(LogWriter& ref, const string rotated_path, const string postprocessor, const double open,
					const double close, const bool terminating)
	: ref(ref), rotated_path(rotated_path), postprocessor(postprocessor), open(open), 
			close(close), terminating(terminating) { }
	
	bool process() { return ref.DoRotate(rotated_path, postprocessor, open, close, terminating); }
private:
	LogWriter &ref;
	const string rotated_path;
	const string postprocessor;
	const double open;
	const double close;
	const bool terminating;
};

class InitMessage : public MessageEvent
{
public:
	InitMessage(LogWriter& ref, const string path, const int num_fields, const LogField* const *fields)
	: ref(ref), path(path), num_fields(num_fields), fields(fields)
	{ }
	bool process() { return ref.DoInit(path, num_fields, fields); }
private:
	LogWriter& ref;
	const string path;
	const int num_fields;
	const LogField * const* fields;
};

class WriteMessage : public MessageEvent
{
public:
	WriteMessage(LogWriter& ref, const int num_fields, LogField* const* fields, LogVal **vals)
	: ref(ref), num_fields(num_fields), fields(fields)
	{ this->vals = vals;  /* TODO: copy vals here; seems like memory corruption is happening :| */ }
	bool process() { bool res = ref.DoWrite(num_fields, fields, vals); ref.DeleteVals(vals, num_fields); return res; }
	WriteMessage& operator= (const WriteMessage& target);
	WriteMessage(const WriteMessage& target);
private:
	LogWriter& ref;
	int num_fields;
	LogField* const* fields;
	LogVal **vals;
};

class BulkWriteMessage : public MessageEvent
{
public:
	bool process();
	void add(const WriteMessage w) { messages.push_back(w); }
	void add(LogWriter& ref, const int num_fields, LogField* const* fields, LogVal **vals) { add(WriteMessage(ref, num_fields, fields, vals)); }
	size_t size() { return messages.size(); }
private:
	std::vector<WriteMessage> messages;

};

class BufferMessage : public MessageEvent
{
public:
	BufferMessage(LogWriter& ref, const bool enabled)
	: ref(ref), enabled(enabled) { }
	bool process() { ref.DoSetBuf(enabled); return true; }
private:
	LogWriter& ref;
	const bool enabled;
};

class FlushMessage : public MessageEvent
{
public:
	FlushMessage(LogWriter& ref)
	: ref(ref) { }
	bool process() { ref.DoFlush(); return true; }
private:
	LogWriter& ref;
};

class FinishMessage : public MessageEvent
{
public:
	FinishMessage(LogWriter& ref)
	: ref(ref) { }

	bool process() { ref.DoFinish(); return true; }
private:
	LogWriter& ref;
};

class LogWriterRegistrar {
public:
	typedef LogWriter* (*InstantiateFunction)(LogEmissary&, QueueInterface<MessageEvent *>&, QueueInterface<MessageEvent *>& );
	typedef bool (*InitFunction)();

	LogWriterRegistrar(const bro_int_t type, const char *name, 
							InitFunction init, InstantiateFunction factory);
	LogWriterRegistrar(const bro_int_t type, const char *name, 
							InstantiateFunction factory);
	/**
	 *  Registers a new log writer so that scripts can use it.
	 *
	 *  This function modifies the shared log_writers object; it is therefore *not*
	 *  thread-safe.
	 *
	 *  @param type BifEnum::Log::WRITER_NAME
	 *  @param name Common name of this writer (e.g. "ASCII") 
	 *  @param init Function to call (once!) before *any* instances are built
	 *  @param factory Function used to instantiate this type of LogWriter (probably MyLogClass::Instantiate) 
	*/
	static void RegisterWriter(const bro_int_t type, const char *name,
								  bool (*init)(), LogWriterRegistrar::InstantiateFunction factory);

	static LogEmissary *LaunchWriterThread(std::string path, size_t num_fields, LogField * const *fields, const bro_int_t type);
private:
	struct LogWriterDefinition
	{
		bro_int_t type;
		InstantiateFunction factory;
		InitFunction init;
		std::string name;
		LogWriterDefinition(const bro_int_t type, InstantiateFunction factory, InitFunction init, const std::string name)
		: type(type), factory(factory), init(init), name(name) { }

		LogWriterDefinition(const bro_int_t type, InstantiateFunction factory, const std::string name)
		: type(type), factory(factory), init(NULL), name(name) { }
	};
	typedef std::map<bro_int_t, LogWriterDefinition> WriterMap;
	typedef WriterMap::iterator WriterMapIterator;
	static WriterMap *writers;

};

#endif

