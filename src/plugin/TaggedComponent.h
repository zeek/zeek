#pragma once

#include <cassert>

namespace zeek::plugin {

/**
 * A class which has a tag of a given type associated with it.
 *
 * @tparam T A ::Tag type or derivative.
 */
template <class T>
class TaggedComponent {
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
	explicit TaggedComponent(typename T::subtype_t subtype = 0);

	/**
	 * Initializes tag by creating the unique tag value for thos componend.
	 * Has to be called exactly once.
	 */
	void InitializeTag();

	/**
	 * @return The component's tag.
	 */
	T Tag() const;

private:
	T tag; /**< The automatically assigned analyzer tag. */
	typename T::subtype_t subtype;
	bool initialized;
	static typename T::type_t type_counter; /**< Used to generate globally
	                                             unique tags. */
};

template <class T>
TaggedComponent<T>::TaggedComponent(typename T::subtype_t subtype)
	{
	tag = T(1,0);
	this->subtype = subtype;
	initialized = false;
	}

template <class T>
void TaggedComponent<T>::InitializeTag()
	{
	assert( initialized == false );
	initialized = true;
	tag = T(++type_counter, subtype);
	}

template <class T>
T TaggedComponent<T>::Tag() const
	{
	assert( initialized );
	return tag;
	}

template <class T> typename T::type_t TaggedComponent<T>::type_counter(0);

} // namespace zeek::plugin
