// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

#include <set>
#include <utility>
#include <string>

#include "zeek/ZeekString.h" // for byte_vec
#include "zeek/util.h" // for bro_int_t

ZEEK_FORWARD_DECLARE_NAMESPACED(IPAddr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IPPrefix, zeek);

namespace zeek {

class File;
class Type;

enum DescType {
	DESC_READABLE,
	DESC_PORTABLE,
	DESC_BINARY,
};

enum DescStyle {
	STANDARD_STYLE,
	RAW_STYLE,
};

class ODesc {
public:
	explicit ODesc(DescType t=DESC_READABLE, File* f=nullptr);

	~ODesc();

	bool IsReadable() const		{ return type == DESC_READABLE; }
	bool IsPortable() const		{ return type == DESC_PORTABLE; }
	bool IsBinary() const		{ return type == DESC_BINARY; }

	bool IsShort() const		{ return is_short; }
	void SetShort()			{ is_short = true; }
	void SetShort(bool s)		{ is_short = s; }

	// Whether we want to have quotes around strings.
	bool WantQuotes() const	{ return want_quotes; }
	void SetQuotes(bool q)	{ want_quotes = q; }

	// Whether we want to print statistics like access time and execution
	// count where available.
	bool IncludeStats() const	{ return include_stats; }
	void SetIncludeStats(bool s)	{ include_stats = s; }

	DescStyle Style() const	{ return style; }
	void SetStyle(DescStyle s)	{ style = s; }

	void SetFlush(bool arg_do_flush)	{ do_flush = arg_do_flush; }

	void EnableEscaping();
	void EnableUTF8();
	void AddEscapeSequence(const char* s) { escape_sequences.insert(s); }
	void AddEscapeSequence(const char* s, size_t n)
	    { escape_sequences.insert(std::string(s, n)); }
	void AddEscapeSequence(const std::string & s)
	    { escape_sequences.insert(s); }
	void RemoveEscapeSequence(const char* s) { escape_sequences.erase(s); }
	void RemoveEscapeSequence(const char* s, size_t n)
	    { escape_sequences.erase(std::string(s, n)); }
	void RemoveEscapeSequence(const std::string & s)
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
	void Add(const std::string& s)	{ AddBytes(s.data(), s.size()); }
	void Add(int i);
	void Add(uint32_t u);
	void Add(int64_t i);
	void Add(uint64_t u);
	void Add(double d, bool no_exp=false);
	void Add(const IPAddr& addr);
	void Add(const IPPrefix& prefix);

	// Add s as a counted string.
	void AddCS(const char* s);

	void AddBytes(const String* s);

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
	void AddRaw(const std::string &s)		{ AddBytesRaw(s.data(), s.size()); }

	// Returns the description as a string.
	const char* Description() const		{ return (const char*) base; }

	const u_char* Bytes() const	{ return (const u_char *) base; }
	byte_vec TakeBytes()
		{
		const void* t = base;
		base = nullptr;
		size = 0;

		// Don't clear offset, as we want to still support
		// subsequent calls to Len().

		return byte_vec(t);
		}

	int Len() const		{ return offset; }

	void Clear();

	// Used to determine recursive types. Records push their types on here;
	// if the same type (by address) is re-encountered, processing aborts.
	bool PushType(const Type* type);
	bool PopType(const Type* type);
	bool FindType(const Type* type);

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
	std::pair<const char*, size_t> FirstEscapeLoc(const char* bytes, size_t n);

	/**
	 * @param start start of string to check for starting with an espace
	 *              sequence.
	 * @param end one byte past the last character in the string.
	 * @return The number of bytes in the escape sequence that the string
	 *         starts with.
	 */
	size_t StartsWithEscapeSequence(const char* start, const char* end);

	DescType type;
	DescStyle style;

	void* base;		// beginning of buffer
	unsigned int offset;	// where we are in the buffer
	unsigned int size;	// size of buffer in bytes

	bool utf8; // whether valid utf-8 sequences may pass through unescaped
	bool escape;	// escape unprintable characters in output?
	bool is_short;
	bool want_quotes;

	int indent_with_spaces;

	using escape_set = std::set<std::string>;
	escape_set escape_sequences; // additional sequences of chars to escape

	File* f;	// or the file we're using.

	int indent_level;
	bool do_flush;
	bool include_stats;

	std::set<const Type*> encountered_types;
};

// Returns a string representation of an object's description.  Used for
// debugging and error messages.  takes a bare pointer rather than an
// IntrusivePtr because the latter is harder to deal with when making
// calls from a debugger like lldb, which is the main use of this function.
class Obj;
extern std::string obj_desc(const Obj* o);

} // namespace zeek
