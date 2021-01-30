// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/Component.h"
#include "zeek/plugin/TaggedComponent.h"
#include "zeek/input/Tag.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(ReaderFrontend, zeek, input);
ZEEK_FORWARD_DECLARE_NAMESPACED(ReaderBackend, zeek, input);

namespace zeek::input {

/**
 * Component description for plugins providing log readers.
 */
class Component : public plugin::Component,
                  public plugin::TaggedComponent<Tag> {
public:
	typedef ReaderBackend* (*factory_callback)(ReaderFrontend* frontend);

	/**
	 * Constructor.
	 *
	 * @param name The name of the provided reader. This name is used
	 * across the system to identify the reader.
	 *
	 * @param factory A factory function to instantiate instances of the
	 * readers's class, which must be derived directly or indirectly from
	 * input::ReaderBackend. This is typically a static \c Instatiate()
	 * method inside the class that just allocates and returns a new
	 * instance.
	 */
	Component(const std::string& name, factory_callback factory);

	/**
	 * Destructor.
	 */
	~Component() override;

	/**
	 * Initialization function. This function has to be called before any
	 * plugin component functionality is used; it is used to add the
	 * plugin component to the list of components and to initialize tags
	 */
	void Initialize() override;

	/**
	 * Returns the reader's factory function.
	 */
	factory_callback Factory() const	{ return factory; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	void DoDescribe(ODesc* d) const override;

private:
	factory_callback factory;
};

} // namespace zeek::input
