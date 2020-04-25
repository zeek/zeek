// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"
#include "../Tag.h"

class EnumVal;

namespace plugin {
template <class T>
class TaggedComponent;
template <class T, class C>
class ComponentManager;
}

namespace logging {

class Manager;
class Component;

/**
 * Class to identify a writer type.
 *
 * The script-layer analogue is Log::Writer.
 */
class Tag : public ::Tag  {
public:
	/*
	 * Copy constructor.
	 */
	Tag(const Tag& other) : ::Tag(other) {}

	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag() : ::Tag() {}

	/**
	 * Destructor.
	 */
	~Tag() {}

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal writer type.
	 */
	explicit operator bool() const	{ return *this != Error; }

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
		return ::Tag::operator==(other);
		}

	/**
	 * Compares two tags for inequality.
	 */
	bool operator!=(const Tag& other) const
		{
		return ::Tag::operator!=(other);
		}

	/**
	 * Compares two tags for less-than relationship.
	 */
	bool operator<(const Tag& other) const
		{
		return ::Tag::operator<(other);
		}

	/**
	 * Returns the \c Log::Writer enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	EnumVal* AsEnumVal() const;

	static const Tag Error;

protected:
	friend class plugin::ComponentManager<Tag, Component>;
	friend class plugin::TaggedComponent<Tag>;

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a logging::Manager
	 * manages the value space internally, so noone else should assign
	 * any main types.
	 *
	 * @param subtype The sub type, which is left to an writer for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Log::Writer.
	 */
	explicit Tag(EnumVal* val) : ::Tag(val) {}
};

}
