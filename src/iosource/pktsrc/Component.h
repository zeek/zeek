// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PLUGIN_COMPONENT_H
#define IOSOURCE_PKTSRC_PLUGIN_COMPONENT_H

#include "../Component.h"

namespace iosource {

class PktSrc;
class PktDumper;

namespace pktsrc {

/**
 * Component description for plugins providing a PktSrc for packet input.
 */
class SourceComponent : public iosource::Component {
public:
	enum InputType { LIVE, TRACE, BOTH };

	typedef PktSrc* (*factory_callback)(const std::string& path, const std::string& filter, bool is_live);

	/**
	 * XXX
	 */
	SourceComponent(const std::string& name, const std::string& prefix, InputType type, factory_callback factory);

	/**
	 * Destructor.
	 */
	virtual ~SourceComponent();

	/**
	 * Returns the prefix passes to the constructor.
	 */
	const std::string& Prefix() const;

	/**
	 * Returns true if packet source instantiated by the component handle
	 * live traffic.
	 */
	bool DoesLive() const;

	/**
	 * Returns true if packet source instantiated by the component handle
	 * offline traces.
	 */
	bool DoesTrace() const;

	/**
	 * Returns the source's factory function.
	 */
	factory_callback Factory() const;

	/**
	 * Generates a human-readable description of the component. This goes
	 * into the output of \c "bro -NN".
	 */
	virtual void Describe(ODesc* d) const;

private:
	std::string prefix;
	InputType type;
	factory_callback factory;
};

/**
 * Component description for plugins providing a PktDumper for packet output.
 *
 * PktDumpers aren't IOSurces but we locate them here to keep them along with
 * the PktSrc.
 */
class DumperComponent : public plugin::Component  {
public:
	typedef PktDumper* (*factory_callback)(const std::string& path, bool append);

	/**
	 * XXX
	 */
	DumperComponent(const std::string& name, const std::string& prefix, factory_callback factory);

	/**
	 * Destructor.
	 */
	~DumperComponent();

	/**
	 * Returns the prefix passes to the constructor.
	 */
	const std::string& Prefix() const;

	/**
	 * Returns the source's factory function.
	 */
	factory_callback Factory() const;

	/**
	 * Generates a human-readable description of the component. This goes
	 * into the output of \c "bro -NN".
	 */
	virtual void Describe(ODesc* d) const;

private:
	std::string prefix;
	factory_callback factory;
};

}
}

#endif
