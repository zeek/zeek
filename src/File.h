// See the file "COPYING" in the main distribution directory for copyright.

#ifndef file_h
#define file_h

#include <fcntl.h>
#include "util.h"
#include "Obj.h"
#include "Attr.h"

# ifdef NEED_KRB5_H
#  include <krb5.h>
# endif // NEED_KRB5_H

class BroType;

class BroFile : public BroObj {
public:
	explicit BroFile(FILE* arg_f);
	BroFile(FILE* arg_f, const char* filename, const char* access);
	BroFile(const char* filename, const char* access, BroType* arg_t = 0);
	~BroFile() override;

	const char* Name() const;

	// Returns false if an error occured.
	int Write(const char* data, int len = 0);

	void Flush()	{ fflush(f); }

	FILE* Seek(long position);	// seek to absolute position

	void SetBuf(bool buffered);	// false=line buffered, true=fully buffered

	BroType* FType() const	{ return t; }

	// Whether the file is open in a general sense; it might
	// not be open as a Unix file due to our management of
	// a finite number of FDs.
	int IsOpen() const	{ return is_open; }

	// Returns true if the close made sense, false if it was already
	// closed, not active, or whatever.
	int Close();

	void Describe(ODesc* d) const override;

	// Rotates the logfile. Returns rotate_info.
	RecordVal* Rotate();

	// Set &raw_output attribute.
	void SetAttrs(Attributes* attrs);

	// Returns the current size of the file, after fresh stat'ing.
	double Size();

	// Close all files which are managed by us.
	static void CloseCachedFiles();

	// Get the file with the given name, opening it if it doesn't yet exist.
	static BroFile* GetFile(const char* name);

	void DisablePrintHook() 	{ print_hook = false; }
	bool IsPrintHookEnabled() const	{ return print_hook; }

	void EnableRawOutput()		{ raw_output = true; }
	bool IsRawOutput() const	{ return raw_output; }

protected:
	BroFile()	{ Init(); }
	void Init();

	/**
	 * If file is given, it's an open file to use already.
	 * If file is not given and mode is, the filename will be opened with that
	 * access mode.
	 */
	bool Open(FILE* f = 0, const char* mode = 0);

	BroFile* Prev()	{ return prev; }
	BroFile* Next()	{ return next; }
	void SetPrev(BroFile* f)	{ prev = f; }
	void SetNext(BroFile* f)	{ next = f; }

	void Suspend();
	void PurgeCache();
	void Unlink();
	void InsertAtBeginning();
	void MoveToBeginning();

	// Returns nil if the file is not active, was in error, etc.
	// (Protected because we do not want anyone to write directly
	// to the file.)
	FILE* File();
	FILE* BringIntoCache();

	// Raises a file_opened event.
	void RaiseOpenEvent();

	FILE* f;
	BroType* t;
	char* name;
	char* access;
	int is_in_cache;	// whether it's currently in the open-file cache
	int is_open;	// whether the file is open in a general sense
	int okay_to_manage;	// we're allowed to cache/uncache
	long position;	// only valid if ! is_in_cache
	BroFile* next;	// doubly-linked list of cached files
	BroFile* prev;
	Attributes* attrs;
	bool buffered;
	double open_time;
	bool print_hook;
	bool raw_output;

	static const int MIN_BUFFER_SIZE = 1024;
};

#endif
