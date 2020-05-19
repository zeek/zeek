// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include <string>
#include <utility>

#include <fcntl.h>

#ifdef NEED_KRB5_H
#include <krb5.h>
#endif // NEED_KRB5_H

#include "Obj.h"
#include "IntrusivePtr.h"
#include "util.h"

class BroType;
class RecordVal;

FORWARD_DECLARE_NAMESPACED(PrintStmt, zeek::detail);
FORWARD_DECLARE_NAMESPACED(Attributes, zeek::detail);

class BroFile final : public BroObj {
public:
	explicit BroFile(FILE* arg_f);
	BroFile(FILE* arg_f, const char* filename, const char* access);
	BroFile(const char* filename, const char* access);
	~BroFile() override;

	const char* Name() const;

	// Returns false if an error occured.
	bool Write(const char* data, int len = 0);

	void Flush()	{ fflush(f); }

	FILE* Seek(long position);	// seek to absolute position

	void SetBuf(bool buffered);	// false=line buffered, true=fully buffered

	[[deprecated("Remove in v4.1.  Use GetType().")]]
	BroType* FType() const	{ return t.get(); }

	const IntrusivePtr<BroType>& GetType() const
		{ return t; }

	// Whether the file is open in a general sense; it might
	// not be open as a Unix file due to our management of
	// a finite number of FDs.
	bool IsOpen() const	{ return is_open; }

	// Returns true if the close made sense, false if it was already
	// closed, not active, or whatever.
	bool Close();

	void Describe(ODesc* d) const override;

	// Rotates the logfile. Returns rotate_info.
	RecordVal* Rotate();

	// Set &raw_output attribute.
	void SetAttrs(zeek::detail::Attributes* attrs);

	// Returns the current size of the file, after fresh stat'ing.
	double Size();

	// Close all files which are currently open.
	static void CloseOpenFiles();

	// Get the file with the given name, opening it if it doesn't yet exist.
	static IntrusivePtr<BroFile> Get(const char* name);
	[[deprecated("Remove in v4.1.  Use BroFile::Get().")]]
	static BroFile* GetFile(const char* name)
		{ return Get(name).release(); }

	void EnableRawOutput()		{ raw_output = true; }
	bool IsRawOutput() const	{ return raw_output; }

protected:

	friend class zeek::detail::PrintStmt;

	BroFile()	{ Init(); }
	void Init();

	/**
	 * If file is given, it's an open file to use already.
	 * If file is not given and mode is, the filename will be opened with that
	 * access mode.
	 */
	bool Open(FILE* f = nullptr, const char* mode = nullptr);

	void Unlink();

	// Returns nil if the file is not active, was in error, etc.
	// (Protected because we do not want anyone to write directly
	// to the file, but the PrintStmt friend uses this to check whether
	// it's really stdout.)
	FILE* File();

	// Raises a file_opened event.
	void RaiseOpenEvent();

	FILE* f;
	IntrusivePtr<BroType> t;
	char* name;
	char* access;
	zeek::detail::Attributes* attrs;
	double open_time;
	bool is_open;	// whether the file is open in a general sense
	bool buffered;
	bool raw_output;

	static const int MIN_BUFFER_SIZE = 1024;

private:
	static std::list<std::pair<std::string, BroFile*>> open_files;
};
