// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <vector>

#include "zeek/ZeekString.h"

namespace zeek::detail {

/**
 * Substrings are essentially Strings, augmented with indexing information
 * required for the Smith-Waterman algorithm. Each substring can be
 * marked as being a common substring of arbitrarily many strings, for each
 * of which we store where the substring starts.
 */
class Substring : public String {

public:
	using Vec = std::vector<Substring*>;

	// An alignment to another string.
	//
	struct BSSAlign {

		BSSAlign(const String* string, int index)
			{ this->string = string; this->index = index; }

		// The other string
		//
		const String* string;

		// Offset in the string that substring
		// starts at, counting from 0.
		//
		int index;
	};

	using BSSAlignVec = std::vector<BSSAlign>;

	explicit Substring(const std::string& string)
		: String(string), _num(), _new(false) { }

	explicit Substring(const String& string)
		: String(string), _num(), _new(false) { }

	Substring(const Substring& bst);

	const Substring& operator=(const Substring& bst);

	// Returns true if this string completely covers the given one.
	// "Covering" means that the substring must be at least as long
	// as the one compared to, and completely covers the range occupied
	// by the given one.
	//
	bool DoesCover(const Substring* bst) const;

	void AddAlignment(const String* string, int index);
	const BSSAlignVec& GetAlignments() const	{ return _aligns; }
	unsigned int GetNumAlignments() const	{ return _aligns.size(); }

	void SetNum(int num)	{ _num = num; }
	int GetNum() const	{ return _num; }

	void MarkNewAlignment(bool mark) { _new = mark; }
	bool IsNewAlignment()	{ return _new; }

	// Helper methods for vectors:
	//
	static VectorVal* VecToPolicy(Vec* vec);
	static Vec* VecFromPolicy(VectorVal* vec);
	static char* VecToString(Vec* vec);
	static String::IdxVec* GetOffsetsVec(const Vec* vec, unsigned int index);

private:
	using DataMap = std::map<std::string, void*>;

	Substring();

	// The alignments registered for this substring.
	BSSAlignVec _aligns;

	// Every substring can have a numerical label.
	int _num;

	// True if this node marks the start of a new alignment.
	bool _new;
};

// A comparison class that sorts Substrings according to the string
// offset value of the nth input string, where "nth" starts from 0.
//
class SubstringCmp {
public:
	explicit SubstringCmp(unsigned int index)	{ _index = index; }
	bool operator()(const Substring* bst1, const Substring* bst2) const;

 private:
	unsigned int _index;
};

// Smith-Waterman Implementation
// ---------------------------------------------------------------------
//

// We support two modes of operation: finding a single optimal alignment,
// and repeated alignments.
//
enum SWVariant {
	SW_SINGLE   = 0,	// return a single, optimum alignment
	SW_MULTIPLE = 1,	// find repeated, non-overlapping alignments
};

// Parameters for Smith-Waterman are stored in this simple record.
//
struct SWParams {
	explicit SWParams(unsigned int min_toklen = 3, SWVariant sw_variant = SW_SINGLE)
		{
		_min_toklen = min_toklen;
		_sw_variant = sw_variant;
		}

	// The minimum string size to report.  For example, min_toklen = 2
	// won't report any common single-letter subsequences.
	unsigned int _min_toklen;

	SWVariant _sw_variant;
};


// The smith_waterman() algorithm finds the longest common subsequence(s)
// of two strings, also known as the best local alignment.  A subsequence
// is a sequence of common substrings.
//
//  s1:         first input string
//  s2:         second input string
//  params:     Smith-Waterman parameters.
//
// Subsequences of a string are any strings based on the original one
// with individual characters left out. Note that this is different
// from the longest common substring problem.
//
// The function returns a vector consisting of all substrings comprising
// the subsequence.  With each string you also get the indices of both
// input strings where the string occurs.  On error, or if no common
// subsequence exists, an empty vector is returned.
//
extern Substring::Vec* smith_waterman(const String* s1,
                                      const String* s2,
                                      SWParams& params);

} // namespace zeek::detail
