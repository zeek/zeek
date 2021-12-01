// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <string>

#include "zeek/Tag.h"
#include "zeek/Val.h"

namespace zeek::logging
	{

/**
 * This class implements a wrapper around zeek::Tag , presenting the same interface as that
 * member object. It previously implemented a full tag object for this type of plugin
 * component, but that functionality was merged into zeek::Tag and the separate tag types were
 * deprecated. This class will eventually be removed per the Zeek deprecation policy.
 */
class [[deprecated("Remove in v5.1. Use zeek::Tag.")]] Tag
	{
public:
	/**
	 * Type for the component's main type.
	 */
	using type_t = zeek::Tag::type_t;

	/**
	 * Type for the component's subtype.
	 */
	using subtype_t = zeek::Tag::subtype_t;

	/**
	 * Returns the tag's main type.
	 */
	zeek::Tag::type_t Type() const { return tag.Type(); }

	/**
	 * Returns the tag's subtype.
	 */
	zeek::Tag::subtype_t Subtype() const { return tag.Subtype(); }

	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag() : tag() { }

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
	Tag(const EnumTypePtr& etype, zeek::Tag::type_t type, zeek::Tag::subtype_t subtype = 0)
		: tag(etype, type, subtype)
		{
		}

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a logging::Manager
	 * manages the value space internally, so noone else should assign
	 * any main types.
	 *
	 * @param subtype The sub type, which is left to a component for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(zeek::Tag::type_t type, zeek::Tag::subtype_t subtype = 0) : tag(type, subtype) { }

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Logger::Tag.
	 */
	explicit Tag(EnumValPtr val) : tag(val) { }

	/*
	 * Copy constructor.
	 */
	Tag(const Tag& other) : tag(other.tag) { }

	/**
	 * Destructor.
	 */
	~Tag() { }

	/**
	 * Assignment operator.
	 */
	Tag& operator=(const Tag& other)
		{
		tag = other.tag;
		return *this;
		}

	/**
	 * Move assignment operator.
	 */
	Tag& operator=(Tag&& other) noexcept
		{
		tag = other.tag;
		return *this;
		}

	/**
	 * Compares two tags for equality.
	 */
	bool operator==(const Tag& other) const { return tag == other.tag; }

	/**
	 * Compares two tags for inequality.
	 */
	bool operator!=(const Tag& other) const { return tag != other.tag; }

	/**
	 * Compares two tags for less-than relationship.
	 */
	bool operator<(const Tag& other) const { return tag < other.tag; }

	/**
	 * Returns the numerical values for main and subtype inside a string
	 * suitable for printing. This is primarily for debugging.
	 */
	std::string AsString() const { return tag.AsString(); }

	/**
	 * Returns the script-layer enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	const EnumValPtr& AsVal() const { return tag.AsVal(); }

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal component type.
	 */
	explicit operator bool() const { return static_cast<bool>(tag); }

private:
	zeek::Tag tag;
	};

	} // namespace zeek::logging
