// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"
#include "../Tag.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(EnumVal, zeek);

namespace zeek::plugin {
	template <class T> class TaggedComponent;
	template <class T, class C> class ComponentManager;
}
namespace plugin {
	template <class T>
	using TaggedComponent [[deprecated("Remove in v4.1. Use zeek::plugin::TaggedComponent instead.")]] =
		zeek::plugin::TaggedComponent<T>;
	template <class T, class C>
	using ComponentManager [[deprecated("Remove in v4.1. Use zeek::plugin::ComponentManager instead.")]] =
		zeek::plugin::ComponentManager<T, C>;
}

namespace file_analysis {

class Component;

/**
 * Class to identify a file analyzer type.
 *
 * The script-layer analogue is Files::Tag.
 */
class Tag : public zeek::Tag {
public:
	/*
	 * Copy constructor.
	 */
	Tag(const Tag& other) : zeek::Tag(other) {}

	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag() : zeek::Tag() {}

	/**
	 * Destructor.
	 */
	~Tag() {}

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal analyzer type.
	 */
	explicit operator bool() const	{ return *this != Error; }

	/**
	 * Assignment operator.
	 */
	Tag& operator=(const Tag& other);

	/**
	 * Compares two tags for equality.
	 */
	bool operator==(const Tag& other) const
		{
		return zeek::Tag::operator==(other);
		}

	/**
	 * Compares two tags for inequality.
	 */
	bool operator!=(const Tag& other) const
		{
		return zeek::Tag::operator!=(other);
		}

	/**
	 * Compares two tags for less-than relationship.
	 */
	bool operator<(const Tag& other) const
		{
		return zeek::Tag::operator<(other);
		}

	/**
	 * Returns the \c Files::Tag enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	const zeek::EnumValPtr& AsVal() const;

	[[deprecated("Remove in v4.1.  Use AsVal() instead.")]]
	zeek::EnumVal* AsEnumVal() const;

	static const Tag Error;

protected:
	friend class zeek::plugin::ComponentManager<Tag, Component>;
	friend class zeek::plugin::TaggedComponent<Tag>;

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a file_analysis::Manager
	 * manages the value space internally, so noone else should assign
	 * main types.
	 *
	 * @param subtype The sub type, which is left to an analyzer for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Files::Tag.
	 */
	explicit Tag(zeek::EnumValPtr val);

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit Tag(zeek::EnumVal* val);
};

}
