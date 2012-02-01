// See the file "COPYING" in the main distribution directory for copyright.
//
// Bridge class between main process and writer threads.

#ifndef LOGGING_WRITERFRONTEND_H
#define LOGGING_WRITERFRONTEND_H

#include "Manager.h"

#include "threading/MsgThread.h"

namespace logging  {

class WriterBackend;

class WriterFrontend {
public:
	WriterFrontend(bro_int_t type);
	virtual ~WriterFrontend();

	// Disables the writers and stop the backend thread.
	void Stop();

	// Interface methods to interact with the writer from the main thread
	// (and only from the main thread), typicalli from the log manager.
	// All these methods forward (via inter-thread messaging) to the
	// corresponding methods of an internally created WriterBackend. See
	// there for documentation.
	//
	// If any of these operations fails, the writer will be automatically
	// (but asynchronoulsy) disabled.

	void Init(string path, int num_fields, const Field* const * fields);
	void Write(int num_fields, Value** vals);
	void SetBuf(bool enabled);
	void Flush();
	void FlushWriteBuffer();
	void Rotate(string rotated_path, double open, double close, bool terminating);
	void Finish();

	// Calling this disable the writer. All methods calls will be no-ops
	// from now on. The Manager will eventually remove disabled writers.
	void SetDisable()	{ disabled = true; }
	bool Disabled()	{ return disabled; }

	const string Path() const	{ return path; }
	int NumFields() const	{ return num_fields; }
	const Field* const * Fields() const	{ return fields; }

protected:
	friend class Manager;

	WriterBackend* backend;
	bool disabled;
	bool initialized;
	bool buf;

	string path;
	int num_fields;
	const Field* const * fields;

	// Buffer for bulk writes.
	static const int WRITER_BUFFER_SIZE = 50;

	int write_buffer_pos;
	Value*** write_buffer;
};

}

#endif
