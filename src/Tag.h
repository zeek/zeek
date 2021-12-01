// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <cstdint>
#include <string>

#include "zeek/IntrusivePtr.h"
#include "zeek/util.h"

namespace zeek
	{

class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;
class EnumType;
using EnumTypePtr = IntrusivePtr<EnumType>;

/**
 * Class to identify an plugin component type.
 *
 * Each component type gets a tag consisting of a main type and subtype. The
 * former is an identifier that's unique across all component classes. The latter is
 * passed through to the component instances for their use, yet not further
 * interpreted by the component infrastructure; it allows a component to
 * branch out into a set of sub-components internally. Jointly, main type and
 * subtype form a component "tag". Each unique tag corresponds to a single
 * "component" from the user's perspective. At the script layer, these tags
 * are mapped into enums of type \c Component::Tag or Files::Tag. Internally,
 * the component::Manager and file_analysis::Manager maintain the mapping of tag
 * to component (and it also assigns them their main types), and
 * component::Component and file_analysis::Component create new tag.
 *
 * The Tag class supports all operations necessary to act as an index in a
 * \c std::map.
 */
class Tag
	{
public:
	/**
	 * Type for the component's main type.
	 */
	using type_t = uint32_t;

	/**
	 * Type for the component's subtype.
	 */
	using subtype_t = uint32_t;

	/**
	 * Returns the tag's main type.
	 */
	type_t Type() const { return type; }

	/**
	 * Returns the tag's subtype.
	 */
	subtype_t Subtype() const { return subtype; }

	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag();

	/**
	 * Constructor.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 *
	 * @param type The main type. Note that the manager class manages the
	 * the value space internally, so noone else should assign main types.
	 *
	 * @param subtype The sub type, which is left to a component for
	 * interpretation. By default it's set to zero.
	 */
	Tag(const EnumTypePtr& etype, type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a component::Manager
	 * manages the value space internally, so noone else should assign
	 * any main types.
	 *
	 * @param subtype The sub type, which is left to an component for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Component::Tag.
	 */
	explicit Tag(EnumValPtr val);

	/*
	 * Copy constructor.
	 */
	Tag(const Tag& other);

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
	Tag& operator=(Tag&& other) noexcept;

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
	 * Returns the numerical values for main and subtype inside a string
	 * suitable for printing. This is primarily for debugging.
	 */
	std::string AsString() const;

	/**
	 * Returns the script-layer enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	const EnumValPtr& AsVal() const { return val; }

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal component type.
	 */
	explicit operator bool() const { return *this != Error; }

	static const Tag Error;

private:
	type_t type = 0; // Main type.
	subtype_t subtype = 0; // Subtype.
	EnumValPtr val; // Script-layer value.
	EnumTypePtr etype;
	};

	} // namespace zeek
