// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_COMPONENT_H
#define PLUGIN_COMPONENT_H

#include <string>

class ODesc;

namespace plugin {

namespace component {

/**
 * Component types.
 */
enum Type {
	READER,	/// An input reader (not currently used).
	WRITER,	/// A logging writer (not currenly used).
	ANALYZER,	/// A protocol analyzer.
	FILE_ANALYZER,	/// A file analyzer.
	IOSOURCE,	/// An I/O source, excluding packet sources.
	PKTSRC,	/// A packet source.
	PKTDUMPER	/// A packet dumper.
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
	 *
	 * @param name A descriptive name for the component.  This name must
	 * be unique across all components of the same type.
	 */
	Component(component::Type type, const std::string& name);

	/**
	 * Destructor.
	 */
	virtual ~Component();

	/**
	 * Returns the compoment's type.
	 */
	component::Type Type() const;

	/**
	 * Returns the compoment's name.
	 */
	const std::string& Name() const;

	/**
	 * Returns a canonocalized version of the components's name.  The
	 * returned name is derived from what's passed to the constructor but
	 * upper-cased and transformed to allow being part of a script-level
	 * ID.
	 */
	const std::string& CanonicalName() const	{ return canon_name; }

	/**
	 * Returns a textual representation of the component. This goes into
	 * the output of "bro -NN".
	 *
	 * By default, this just outputs the type and the name. Derived
	 * versions can override DoDescribe() to add type specific details.
	 *
	 * @param d The description object to use.
	 */
	void Describe(ODesc* d) const;

protected:
	/**
	 * Adds type specific information to the output of Describe().
	 *
	 * The default version does nothing.
	 *
	 * @param d The description object to use.
	  */
	virtual void DoDescribe(ODesc* d) const	{ }

private:
	// Disable.
	Component(const Component& other);
	Component operator=(const Component& other);

	component::Type type;
	std::string name;
	std::string canon_name;
};

}

#endif
