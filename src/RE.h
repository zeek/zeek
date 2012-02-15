// See the file "COPYING" in the main distribution directory for copyright.

#ifndef re_h
#define re_h

#include "Obj.h"
#include "Dict.h"
#include "BroString.h"
#include "CCL.h"
#include "EquivClass.h"

#include <ctype.h>
typedef int (*cce_func)(int);

class CCL;
class NFA_Machine;
class DFA_Machine;
class Specific_RE_Matcher;
class RE_Matcher;
class DFA_State;

declare(PDict,char);
declare(PDict,CCL);
declare(PList,CCL);

extern int case_insensitive;
extern CCL* curr_ccl;
extern NFA_Machine* nfa;
extern Specific_RE_Matcher* rem;
extern const char* RE_parse_input;

extern int re_lex(void);
extern int clower(int);
extern void synerr(const char str[]);

typedef int_list AcceptingSet;
typedef name_list string_list;

typedef enum { MATCH_ANYWHERE, MATCH_EXACTLY, } match_type;

// A "specific" RE matcher will match one type of pattern: either
// MATCH_ANYWHERE or MATCH_EXACTLY.

class Specific_RE_Matcher {
public:
	Specific_RE_Matcher(match_type mt, int multiline=0);
	~Specific_RE_Matcher();

	void AddPat(const char* pat);

	void SetPat(const char* pat)	{ pattern_text = copy_string(pat); }

	int Compile(int lazy = 0);

	// The following is vestigial from flex's use of "{name}" definitions.
	// It's here because at some point we may want to support such
	// functionality.
	const char* LookupDef(const char* def);

	void InsertCCL(const char* txt, CCL* ccl) { ccl_dict.Insert(txt, ccl); }
	int InsertCCL(CCL* ccl)
		{
		ccl_list.append(ccl);
		return ccl_list.length() - 1;
		}
	CCL* LookupCCL(const char* txt)	{ return ccl_dict.Lookup(txt); }
	CCL* LookupCCL(int index)	{ return ccl_list[index]; }
	CCL* AnyCCL();

	void ConvertCCLs();

	int MatchAll(const char* s);
	int MatchAll(const BroString* s);

	// Compiles a set of regular expressions simultaniously.
	// 'idx' contains indizes associated with the expressions.
	// On matching, the set of indizes is returned which correspond
	// to the matching expressions.  (idx must not contain zeros).
	int CompileSet(const string_list& set, const int_list& idx);

	// Returns the position in s just beyond where the first match
	// occurs, or 0 if there is no such position in s.  Note that
	// if the pattern matches empty strings, matching continues
	// in an attempt to match at least one character.
	int Match(const char* s);
	int Match(const BroString* s);

	int LongestMatch(const char* s);
	int LongestMatch(const BroString* s);
	int LongestMatch(const u_char* bv, int n);

	EquivClass* EC()		{ return &equiv_class; }

	const char* PatternText() const	{ return pattern_text; }

	DFA_Machine* DFA() const		{ return dfa; }

	void Dump(FILE* f);

	unsigned int MemoryAllocation() const;

protected:
	void AddAnywherePat(const char* pat);
	void AddExactPat(const char* pat);

	// Used by the above.  orig_fmt is the format to use when building
	// up a new pattern_text from the given pattern; app_fmt is for when
	// appending to an existing pattern_text.
	void AddPat(const char* pat, const char* orig_fmt, const char* app_fmt);

	int MatchAll(const u_char* bv, int n);
	int Match(const u_char* bv, int n);

	match_type mt;
	int multiline;
	char* pattern_text;

	PDict(char) defs;
	PDict(CCL) ccl_dict;
	PList(CCL) ccl_list;
	EquivClass equiv_class;
	int* ecs;
	DFA_Machine* dfa;
	CCL* any_ccl;
	AcceptingSet* accepted;
};

class RE_Match_State {
public:
	RE_Match_State(Specific_RE_Matcher* matcher)
		{
		dfa = matcher->DFA() ? matcher->DFA() : 0;
		ecs = matcher->EC()->EquivClasses();
		current_pos = -1;
		current_state = 0;
		}

	const AcceptingSet* Accepted() const	{ return &accepted; }
	const int_list* MatchPositions() const	{ return &match_pos; }

	// Returns the number of bytes feeded into the matcher so far
	int Length()	{ return current_pos; }

	// Returns true if this inputs leads to at least one new match.
	// If clear is true, starts matching over.
	bool Match(const u_char* bv, int n, bool bol, bool eol, bool clear);

	void Clear()
		{
		current_pos = -1;
		current_state = 0;
		accepted.clear();
		match_pos.clear();
		}

protected:
	DFA_Machine* dfa;
	int* ecs;

	AcceptingSet accepted;
	int_list match_pos;
	DFA_State* current_state;
	int current_pos;
};

class RE_Matcher : SerialObj {
public:
	RE_Matcher();
	RE_Matcher(const char* pat);
	virtual ~RE_Matcher();

	void AddDef(const char* defn_name, const char* defn_val);
	void AddPat(const char* pat);

	int Compile(int lazy = 0);

	// Returns true if s exactly matches the pattern, false otherwise.
	int MatchExactly(const char* s)
		{ return re_exact->MatchAll(s); }
	int MatchExactly(const BroString* s)
		{ return re_exact->MatchAll(s); }

	// Returns the position in s just beyond where the first match
	// occurs, or 0 if there is no such position in s.  Note that
	// if the pattern matches empty strings, matching continues
	// in an attempt to match at least one character.
	int MatchAnywhere(const char* s)
		{ return re_anywhere->Match(s); }
	int MatchAnywhere(const BroString* s)
		{ return re_anywhere->Match(s); }

	// Note: it matches the *longest* prefix and returns the
	// length of matched prefix. It returns -1 on mismatch.
	int MatchPrefix(const char* s)
		{ return re_exact->LongestMatch(s); }
	int MatchPrefix(const BroString* s)
		{ return re_exact->LongestMatch(s); }
	int MatchPrefix(const u_char* s, int n)
		{ return re_exact->LongestMatch(s, n); }

	const char* PatternText() const	{ return re_exact->PatternText(); }
	const char* AnywherePatternText() const	{ return re_anywhere->PatternText(); }

	bool Serialize(SerialInfo* info) const;
	static RE_Matcher* Unserialize(UnserialInfo* info);

	unsigned int MemoryAllocation() const
		{
		return padded_sizeof(*this)
			+ (re_anywhere ? re_anywhere->MemoryAllocation() : 0)
			+ (re_exact ? re_exact->MemoryAllocation() : 0);
		}

protected:
	DECLARE_SERIAL(RE_Matcher);

	Specific_RE_Matcher* re_anywhere;
	Specific_RE_Matcher* re_exact;
};

declare(PList, RE_Matcher);
typedef PList(RE_Matcher) re_matcher_list;

extern RE_Matcher* RE_Matcher_conjunction(const RE_Matcher* re1, const RE_Matcher* re2);
extern RE_Matcher* RE_Matcher_disjunction(const RE_Matcher* re1, const RE_Matcher* re2);

#endif
