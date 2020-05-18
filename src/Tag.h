// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <string>

#include <stdint.h>

class EnumVal;
class EnumType;

/**
 * Class to identify an analyzer type.
 *
 * Each analyzer type gets a tag consisting of a main type and subtype. The
 * former is an identifier that's unique across all analyzer classes. The latter is
 * passed through to the analyzer instances for their use, yet not further
 * interpreted by the analyzer infrastructure; it allows an analyzer to
 * branch out into a set of sub-analyzers internally. Jointly, main type and
 * subtype form an analyzer "tag". Each unique tag corresponds to a single
 * "analyzer" from the user's perspective. At the script layer, these tags
 * are mapped into enums of type \c Analyzer::Tag or Files::Tag. Internally,
 * the analyzer::Manager and file_analysis::Manager maintain the mapping of tag
 * to analyzer (and it also assigns them their main types), and
 * analyzer::Component and file_analysis::Component create new tag.
 *
 * The Tag class supports all operations necessary to act as an index in a
 * \c std::map.
 */
class Tag  {
public:
	/**
	 * Type for the analyzer's main type.
	 */
	typedef uint32_t type_t;

	/**
	 * Type for the analyzer's subtype.
	 */
	typedef uint32_t subtype_t;

	/**
	 * Returns the tag's main type.
	 */
	type_t Type() const 	{ return type; }

	/**
	 * Returns the tag's subtype.
	 */
	subtype_t Subtype() const 	{ return subtype; }

	/**
	 * Returns the numerical values for main and subtype inside a string
	 * suitable for printing. This is primarily for debugging.
	 */
	std::string AsString() const;

protected:
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
	 * Assignment operator.
	 */
	Tag& operator=(const Tag& other);

	/**
	 * Move assignment operator.
	 */
	Tag& operator=(const Tag&& other) noexcept;

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

	/**
	 * Returns the script-layer enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	EnumVal* AsEnumVal(EnumType* etype) const;

	/**
	 * Constructor.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 *
	 * @param type The main type. Note that the manager class manages the
	 * the value space internally, so noone else should assign main types.
	 *
	 * @param subtype The sub type, which is left to an analyzer for
	 * interpretation. By default it's set to zero.
	 */
	Tag(EnumType* etype, type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Analyzer::Tag.
	 */
	explicit Tag(EnumVal* val);

private:
	type_t type;            // Main type.
	subtype_t subtype;      // Subtype.
	mutable EnumVal* val;   // Script-layer value.
};
