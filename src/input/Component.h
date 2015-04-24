// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_COMPONENT_H
#define INPUT_COMPONENT_H

#include "Tag.h"
#include "plugin/Component.h"
#include "plugin/TaggedComponent.h"

namespace input {

class ReaderFrontend;
class ReaderBackend;

/**
 * Component description for plugins providing log readers.
 */
class Component : public plugin::Component,
		  public plugin::TaggedComponent<input::Tag> {
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
	~Component();

	/**
	 * Returns the reader's factory function.
	 */
	factory_callback Factory() const	{ return factory; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	virtual void DoDescribe(ODesc* d) const;

private:
	factory_callback factory;
};

}

#endif
