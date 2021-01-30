// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include "zeek/file_analysis/Tag.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/TaggedComponent.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
namespace zeek {
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;
}

ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek, file_analysis);
ZEEK_FORWARD_DECLARE_NAMESPACED(Analyzer, zeek, file_analysis);
ZEEK_FORWARD_DECLARE_NAMESPACED(Manager, zeek, file_analysis);

namespace zeek::file_analysis {

/**
 * Component description for plugins providing file analyzers.
 *
 * A plugin can provide a specific file analyzer by registering this
 * analyzer component, describing the analyzer.
 */
class Component : public plugin::Component,
                  public plugin::TaggedComponent<file_analysis::Tag> {
public:
	using factory_function = Analyzer* (*)(RecordValPtr args, File* file);

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
	Component(const std::string& name, factory_function factory, Tag::subtype_t subtype = 0);

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
	 * Returns the analyzer's factory function.
	 */
	factory_function FactoryFunction() const
		{ return factory_func; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	void DoDescribe(ODesc* d) const override;

private:
	friend class Manager;

	factory_function factory_func;	// The analyzer's factory callback.
};

} // namespace zeek::file_analysis
