
#ifndef ANALYZER_TAG_H
#define ANALYZER_TAG_H

// Each kind of analyzer gets a tag consisting of a main type and subtype.
// The former is an identifier that's unique all analyzer classes. The latter
// is passed through analyzer instances, yet not further interpreted by the
// analyzer infrastructure; it allows an analyzer to branch out into a set of
// sub-analyzers internally. Jointly, main type and subtype form an analyzer
// "tag". Each unique tag corresponds to a single "analyzer" from the user's
// perspective.

#include "config.h"
#include "util.h"

class EnumVal;

namespace analyzer {

/// This has supports all operations to be used as a map index.
class Tag  {
public:
	typedef uint32 type_t;
	typedef uint32 subtype_t;

	Tag(type_t type, subtype_t subtype = 0);
	Tag(EnumVal* val);
	Tag(const Tag& other);
	Tag(); // Tag::ERROR value

	type_t Type() const 	{ return type; }
	subtype_t Subtype() const 	{ return subtype; }

	// Returns an identifying integer for this tag that's guaranteed to
	// be unique across all tags.
	EnumVal* Val();

	std::string AsString() const;

	operator bool() const	{ return *this != Tag(); }
	bool operator==(const Tag& other) const	{ return type == other.type && subtype == other.subtype; }
	bool operator!=(const Tag& other) const	{ return type != other.type || subtype != other.subtype; }
	bool operator<(const Tag& other) const
		{
		return type != other.type ? type < other.type : (subtype < other.subtype);
		}


	static Tag ERROR;

private:
	type_t type;
	subtype_t subtype;
	EnumVal* val;
};

}

#endif
