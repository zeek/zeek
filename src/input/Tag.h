// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_TAG_H
#define INPUT_TAG_H

#include "zeek-config.h"
#include "util.h"
#include "../Tag.h"
#include "plugin/TaggedComponent.h"
#include "plugin/ComponentManager.h"

class EnumVal;

namespace input {

class Manager;
class Component;

/**
 * Class to identify a reader type.
 *
 * The script-layer analogue is Input::Reader.
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
	 * legal reader type.
	 */
	explicit operator bool() const	{ return *this != Tag(); }

	/**
	 * Assignment operator.
	 */
	Tag& operator=(const Tag& other);

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
	 * Returns the \c Input::Reader enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	EnumVal* AsEnumVal() const;

	static Tag Error;

protected:
	friend class plugin::ComponentManager<Tag, Component>;
	friend class plugin::TaggedComponent<Tag>;

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a input::Manager
	 * manages the value space internally, so noone else should assign
	 * any main types.
	 *
	 * @param subtype The sub type, which is left to an reader for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Input::Reader.
	 */
	explicit Tag(EnumVal* val) : ::Tag(val) {}
};

}

#endif
