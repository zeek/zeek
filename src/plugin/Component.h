// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_COMPONENT_H
#define PLUGIN_COMPONENT_H

class ODesc;

namespace plugin {

namespace component {

/**
 * Component types. 
 */
enum Type {
	READER,	/// An input reader (not currently used).
	WRITER,	/// An logging writer (not currenly used).
	ANALYZER,	/// A protocol analyzer.
	FILE_ANALYZER	/// A file analyzer.
	};
}

/**
 * Base class for plugin components. A component is a specific piece of
 * functionality that a plugin provides, such as a protocol analyzer or a log
 * writer. 
 */
class Component
{
public:
	/**
	 * Constructor.
	 *
	 * @param type The type of the compoment.
	 */
	Component(component::Type type);

	/**
	 * Destructor.
	 */
	virtual ~Component();

	/**
	 * Returns the compoment's type.
	 */
	component::Type Type() const;

	/**
	 * Returns a descriptive name for the analyzer. This name must be
	 * unique across all components of the same type.
	 */
	virtual const char* Name() const = 0;

	/**
	 * Returns a textual representation of the component. The default
	 * version just output the type. Derived version should call the
	 * parent's implementation and that add further information.
	 *
	 * @param d The description object to use.
	 */
	virtual void Describe(ODesc* d) const;

private:
	component::Type type;
};

}

#endif
