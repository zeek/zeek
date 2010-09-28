// $Id: Desc.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef descriptor_h
#define descriptor_h

#include <stdio.h>
#include "BroString.h"

typedef enum {
	DESC_READABLE,
	DESC_PORTABLE,
	DESC_BINARY,
} desc_type;

typedef enum {
	STANDARD_STYLE,
	ALTERNATIVE_STYLE,
} desc_style;

class BroFile;

class ODesc {
public:
	ODesc(desc_type t=DESC_READABLE, BroFile* f=0);

	~ODesc();

	int IsReadable() const		{ return type == DESC_READABLE; }
	int IsPortable() const		{ return type == DESC_PORTABLE; }
	int IsBinary() const		{ return type == DESC_BINARY; }

	int IsShort() const		{ return is_short; }
	void SetShort()			{ is_short = 1; }
	void SetShort(int s)		{ is_short = s; }

	// Whether we want to have quotes around strings.
	int WantQuotes() const	{ return want_quotes; }
	void SetQuotes(int q)	{ want_quotes = q; }

	// Whether we want to print statistics like access time and execution
	// count where available.
	int IncludeStats() const	{ return include_stats; }
	void SetIncludeStats(int s)	{ include_stats = s; }

	desc_style Style() const	{ return style; }
	void SetStyle(desc_style s)	{ style = s; }

	void SetFlush(int arg_do_flush)	{ do_flush = arg_do_flush; }

	void PushIndent();
	void PopIndent();
	int GetIndentLevel() const	{ return indent_level; }

	void Add(const char* s, int do_indent=1);
	void AddN(const char* s, int len)	{ AddBytes(s, len); }
	void Add(int i);
	void Add(uint32 u);
#ifdef USE_INT64
	void Add(int64 i);
	void Add(uint64 u);
#endif
	void Add(double d);

	// Add s as a counted string.
	void AddCS(const char* s);

	void AddBytes(const BroString* s);

	void Add(const char* s1, const char* s2)
		{ Add(s1); Add(s2); }

	void AddSP(const char* s1, const char* s2)
		{ Add(s1); AddSP(s2); }

	void AddSP(const char* s )
		{ Add(s); SP(); }

	void AddCount(bro_int_t n)
		{
		if ( ! IsReadable() )
			{
			Add(n);
			SP();
			}
		}

	void SP()	{
			if ( ! IsBinary() )
				Add(" ", 0);
			}
	void NL()	{
			if ( ! IsBinary() && ! is_short )
				Add("\n", 0);
			}

	// Returns the description as a string.
	const char* Description() const		{ return (const char*) base; }

	const u_char* Bytes() const	{ return (const u_char *) base; }
	byte_vec TakeBytes()
		{
		const void* t = base;
		base = 0;
		size = 0;

		// Don't clear offset, as we want to still support
		// subsequent calls to Len().

		return byte_vec(t);
		}

	int Len() const		{ return offset; }

protected:
	void Indent();

	void AddBytes(const void* bytes, unsigned int n);

	// Make buffer big enough for n bytes beyond bufp.
	void Grow(unsigned int n);

	void OutOfMemory();

	desc_type type;
	desc_style style;

	void* base;		// beginning of buffer
	unsigned int offset;	// where we are in the buffer
	unsigned int size;	// size of buffer in bytes

	BroFile* f;	// or the file we're using.

	int indent_level;
	int is_short;
	int want_quotes;
	int do_flush;
	int include_stats;
};

#endif
