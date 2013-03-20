
#ifndef PLUGIN_COMPONENT_H
#define PLUGIN_COMPONENT_H

class ODesc;

namespace plugin {

namespace component {
	enum Type {
		READER,
		WRITER,
		ANALYZER
	};
}

namespace input    { class PluginComponent; }
namespace logging  { class PluginComponent; }
namespace analyzer { class PluginComponent; }

class Component
{
public:
	Component(component::Type type);
	virtual ~Component();

	component::Type Type() const;

	virtual void Describe(ODesc* d);

private:
	component::Type type;
};

}

#endif
