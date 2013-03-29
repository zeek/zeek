
#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include <list>
#include <string>

#include "Macros.h"

class ODesc;

namespace plugin  {

class Manager;
class Component;

struct Description {
	std::string name;
	std::string description;
	std::string url;
	int version;
	int api_version;

	Description();
	void Describe(ODesc* d);
	};

struct BifItem {
	// Values must match the integers bifcl generates.
	enum Type { FUNCTION = 1, EVENT = 2, CONSTANT = 3, GLOBAL = 4, TYPE = 5 };

	std::string id;
	Type type;
};

class Plugin {
public:
	typedef std::list<Component *> component_list;
	typedef std::list<BifItem> bif_item_list;

	Plugin();
	virtual ~Plugin();

	Description GetDescription() const;
	void SetDescription(Description& desc);

	component_list Components();

	void InitBif();

	// Must be called after InitBif() only.
	const bif_item_list& BifItems(); 

	virtual void Init();
	virtual void Done();

	void Describe(ODesc* d);

protected:
	/**
	 * Takes ownership.
	 */
	void AddComponent(Component* c);

	typedef std::list<std::pair<std::string, int> > bif_init_func_result;
	typedef bif_init_func_result (*bif_init_func)();
	void AddBifInitFunction(bif_init_func c);

private:
	typedef std::list<bif_init_func> bif_init_func_list;

	plugin::Description description;
	component_list components;
	bif_item_list bif_items;
	bif_init_func_list bif_inits;
};

}

#endif
