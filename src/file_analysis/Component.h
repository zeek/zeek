// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYZER_COMPONENT_H
#define FILE_ANALYZER_COMPONENT_H

#include "Tag.h"
#include "plugin/Component.h"
#include "plugin/TaggedComponent.h"

#include "Val.h"

#include "../bro-config.h"
#include "../util.h"

namespace file_analysis {

class File;
class Analyzer;

/**
 * Component description for plugins providing file analyzers.
 *
 * A plugin can provide a specific file analyzer by registering this
 * analyzer component, describing the analyzer.
 */
class Component : public plugin::Component,
                  public plugin::TaggedComponent<file_analysis::Tag> {
public:
	typedef Analyzer* (*factory_callback)(RecordVal* args, File* file);

	/**
	 * Constructor.
	 *
	 * @param name The name of the provided analyzer. This name is used
	 * across the system to identify the analyzer, e.g., when calling
	 * file_analysis::Manager::InstantiateAnalyzer with a name.
	 *
	 * @param factory A factory function to instantiate instances of the
	 * analyzer's class, which must be derived directly or indirectly
	 * from file_analysis::Analyzer. This is typically a static \c
	 * Instatiate() method inside the class that just allocates and
	 * returns a new instance.
	 *
	 * @param subtype A subtype associated with this component that
	 * further distinguishes it. The subtype will be integrated into the
	 * analyzer::Tag that the manager associates with this analyzer, and
	 * analyzer instances can accordingly access it via analyzer::Tag().
	 * If not used, leave at zero.
	 */
	Component(const std::string& name, factory_callback factory, Tag::subtype_t subtype = 0);

	/**
	 * Destructor.
	 */
	~Component();

	/**
	 * Returns the analyzer's factory function.
	 */
	factory_callback Factory() const	{ return factory; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	virtual void DoDescribe(ODesc* d) const;

private:
	factory_callback factory;	// The analyzer's factory callback.
};

}

#endif
