#pragma once

#include <cassert>

#include "zeek/Tag.h"
#include "zeek/Type.h"

namespace zeek::plugin
	{

/**
 * A class which has a tag of a given type associated with it.
 */
class TaggedComponent
	{
public:
	/**
	 * Constructor for TaggedComponend. Note that a unique value
	 * for this component is only created when InitializeTag is
	 * called.
	 *
	 * @param subtype A subtype associated with this component that
	 * further distinguishes it. The subtype will be integrated into
	 * the Tag that the manager associates with this component,
	 * and component instances can accordingly access it via Tag().
	 * If not used, leave at zero.
	 */
	explicit TaggedComponent(Tag::subtype_t subtype = 0, zeek::EnumTypePtr etype = nullptr);

	/**
	 * Initializes tag by creating the unique tag value for thos componend.
	 * Has to be called exactly once.
	 */
	void InitializeTag();

	/**
	 * @return The component's tag.
	 */
	zeek::Tag Tag() const;

private:
	zeek::Tag tag; /**< The automatically assigned analyzer tag. */
	Tag::subtype_t subtype;
	bool initialized;
	EnumTypePtr etype;
	static Tag::type_t type_counter; /**< Used to generate globally
	                                             unique tags. */
	};

	} // namespace zeek::plugin
