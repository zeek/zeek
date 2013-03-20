
#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include <list>
#include <string>

class ODesc;

namespace plugin  {

class Manager;
class Component;

static const int API_VERSION = 1;
static const int API_BUILTIN = -1;
static const int API_ERROR = -2;

struct Description {
	std::string name;
	std::string description;
	std::string url;
	int version;
	int api_version;

	Description();
	void Describe(ODesc* d);
	};

class Plugin {
public:
	typedef std::list<Component *> component_list;

	Plugin();
	virtual ~Plugin();

	Description GetDescription() const;
	void SetDescription(Description& desc);

	component_list Components();

	virtual void Init();
	virtual void Done();

	void Describe(ODesc* d);

protected:
	/**
	 * Takes ownership.
	 */
	void AddComponent(Component* c);

private:
	plugin::Description description;
	component_list components;
};

}

#endif
