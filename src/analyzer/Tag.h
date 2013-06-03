// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_TAG_H
#define ANALYZER_TAG_H

#include "config.h"
#include "util.h"

class EnumVal;

namespace analyzer {

class Manager;
class Component;

/**
 * Class to identify an analyzer type.
 *
 * Each analyzer type gets a tag consisting of a main type and subtype. The
 * former is an identifier that's unique all analyzer classes. The latter is
 * passed through to the analyzer instances for their use, yet not further
 * interpreted by the analyzer infrastructure; it allows an analyzer to
 * branch out into a set of sub-analyzers internally. Jointly, main type and
 * subtype form an analyzer "tag". Each unique tag corresponds to a single
 * "analyzer" from the user's perspective. At the script layer, these tags
 * are mapped into enums of type \c Analyzer::Tag. Internally, the
 * analyzer::Mangager maintains the mapping of tag to analyzer (and it also
 * assigns them their main types), and analyzer::Component creates new
 * tags.
 *
 * The Tag class supports all operations necessary to act as an index in a
 * \c std::map.
 */
class Tag  {
public:
	/**
	 * Type for the analyzer's main type.
	 */
	typedef uint32 type_t;

	/**
	 * Type for the analyzer's subtype.
	 */
	typedef uint32 subtype_t;

	/*
	 * Copy constructor.
	 */
	Tag(const Tag& other);

	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag();

	/**
	 * Destructor.
	 */
	~Tag();

	/**
	 * Returns the tag's main type.
	 */
	type_t Type() const 	{ return type; }

	/**
	 * Returns the tag's subtype.
	 */
	subtype_t Subtype() const 	{ return subtype; }

	/**
	 * Returns the \c Analyzer::Tag enum that corresponds to this tag.
	 * The returned value is \a does not have its ref-count increased.
	 */
	EnumVal* AsEnumVal() const;

	/**
	 * Returns the numerical values for main and subtype inside a string
	 * suitable for printing. This is primarily for debugging.
	 */
	std::string AsString() const;

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal analyzer type.
	 */
	operator bool() const	{ return *this != Tag(); }

	/**
	 * Assignment operator.
	 */
	Tag& operator=(const Tag& other);

	/**
	 * Compares two tags for equality.
	 */
	bool operator==(const Tag& other) const
		{
		return type == other.type && subtype == other.subtype;
		}

	/**
	 * Compares two tags for inequality.
	 */
	bool operator!=(const Tag& other) const
		{
		return type != other.type || subtype != other.subtype;
		}

	/**
	 * Compares two tags for less-than relationship.
	 */
	bool operator<(const Tag& other) const
		{
		return type != other.type ? type < other.type : (subtype < other.subtype);
		}

	static Tag Error;

protected:
	friend class analyzer::Manager;
	friend class analyzer::Component;

	/**
	 * Constructor. Note 
	 *
	 * @param type The main type. Note that the \a analyzer::Manager
	 * manages the value space internally, so noone else should assign
	 * any main tyoes.
	 *
	 * @param subtype The sub type, which is left to an analyzer for
	 * interpretation. By default it's set to zero.
	 */
	Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enuam value of script type \c Analyzer::Tag.
	 */
	Tag(EnumVal* val);

private:
	type_t type;		// Main type.
	subtype_t subtype;	// Subtype.
	mutable EnumVal* val;	// Analyzer::Tag value.
};

}

#endif
