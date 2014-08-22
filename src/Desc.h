// See the file "COPYING" in the main distribution directory for copyright.

#ifndef descriptor_h
#define descriptor_h

#include <stdio.h>
#include <set>
#include <utility>

#include "BroString.h"

typedef enum {
	DESC_READABLE,
	DESC_PORTABLE,
	DESC_BINARY,
} desc_type;

typedef enum {
	STANDARD_STYLE,
	ALTERNATIVE_STYLE,
	RAW_STYLE,
} desc_style;

class BroFile;
class IPAddr;
class IPPrefix;

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

	void EnableEscaping();
	void AddEscapeSequence(const char* s) { escape_sequences.insert(s); }
	void AddEscapeSequence(const char* s, size_t n)
	    { escape_sequences.insert(string(s, n)); }
	void AddEscapeSequence(const string & s)
	    { escape_sequences.insert(s); }
	void RemoveEscapeSequence(const char* s) { escape_sequences.erase(s); }
	void RemoveEscapeSequence(const char* s, size_t n)
	    { escape_sequences.erase(string(s, n)); }
	void RemoveEscapeSequence(const string & s)
	    { escape_sequences.erase(s); }

	void PushIndent();
	void PopIndent();
	void PopIndentNoNL();
	int GetIndentLevel() const	{ return indent_level; }
	void ClearIndentLevel() { indent_level = 0; }

	int IndentSpaces() const	{ return indent_with_spaces; }
	void SetIndentSpaces(int i)	{ indent_with_spaces = i; }

	void Add(const char* s, int do_indent=1);
	void AddN(const char* s, int len)	{ AddBytes(s, len); }
	void Add(const string& s)	{ AddBytes(s.data(), s.size()); }
	void Add(int i);
	void Add(uint32 u);
	void Add(int64 i);
	void Add(uint64 u);
	void Add(double d);
	void Add(const IPAddr& addr);
	void Add(const IPPrefix& prefix);

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

	// Bypasses the escaping enabled via SetEscape().
	void AddRaw(const char* s, int len)	{ AddBytesRaw(s, len); }
	void AddRaw(const string &s)		{ AddBytesRaw(s.data(), s.size()); }

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

	void Clear();

protected:
	void Indent();

	void AddBytes(const void* bytes, unsigned int n);
	void AddBytesRaw(const void* bytes, unsigned int n);

	// Make buffer big enough for n bytes beyond bufp.
	void Grow(unsigned int n);

	/**
	 * Returns the location of the first place in the bytes to be hex-escaped.
	 *
	 * @param bytes the starting memory address to start searching for
	 *        escapable character.
	 * @param n the maximum number of bytes to search.
	 * @return a pair whose first element represents a starting memory address
	 *         to be escaped up to the number of characters indicated by the
	 *         second element.  The first element may be 0 if nothing is
	 *         to be escaped.
	 */
	pair<const char*, size_t> FirstEscapeLoc(const char* bytes, size_t n);

	/**
	 * @param start start of string to check for starting with an espace
	 *              sequence.
	 * @param end one byte past the last character in the string.
	 * @return The number of bytes in the escape sequence that the string
	 *         starts with.
	 */
	size_t StartsWithEscapeSequence(const char* start, const char* end);

	desc_type type;
	desc_style style;

	void* base;		// beginning of buffer
	unsigned int offset;	// where we are in the buffer
	unsigned int size;	// size of buffer in bytes

	bool escape;	// escape unprintable characters in output?
	typedef set<string> escape_set;
	escape_set escape_sequences; // additional sequences of chars to escape

	BroFile* f;	// or the file we're using.

	int indent_level;
	int is_short;
	int want_quotes;
	int do_flush;
	int include_stats;
	int indent_with_spaces;
};

#endif
