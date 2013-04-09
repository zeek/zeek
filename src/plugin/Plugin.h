
#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include <list>
#include <string>

#include "Macros.h"

class ODesc;

namespace plugin  {

class Manager;
class Component;

class BifItem {
public:
	// Values must match the integers bifcl generates.
	enum Type { FUNCTION = 1, EVENT = 2, CONSTANT = 3, GLOBAL = 4, TYPE = 5 };

	BifItem(const std::string& id, Type type);
	BifItem(const BifItem& other);
	BifItem& operator=(const BifItem& other);
	~BifItem();

	const char* GetID() const	{ return id; }
	Type GetType() const	{ return type; }

private:
	const char* id;
	Type type;
};

inline BifItem::BifItem(const std::string& arg_id, Type arg_type)
	{
	id = copy_string(arg_id.c_str());
	type = arg_type;
	}

class Plugin {
public:
	typedef std::list<Component *> component_list;
	typedef std::list<BifItem> bif_item_list;

	Plugin();
	virtual ~Plugin();

	const char* Name();
	const char* Description();
	int Version();
	int APIVersion();

	component_list Components();

	void InitBif();

	// Must be called after InitBif() only.
	bif_item_list BifItems();

	virtual void Init();
	virtual void Done();

	void Describe(ODesc* d);

protected:
	typedef std::list<std::pair<const char*, int> > bif_init_func_result;
	typedef bif_init_func_result (*bif_init_func)();

	void SetName(const char* name);
	void SetDescription(const char* descr);
	void SetVersion(int version);
	void SetAPIVersion(int version);

	/**
	 * Takes ownership.
	 */
	void AddComponent(Component* c);

	/**
	 * Can be overriden by derived class to inform the plugin about
	 * further BiF items they provide on their own (i.e., outside of the
	 * standard mechanism processing *.bif files automatically.). This
	 * information is for information purpuses only and will show up in
	 * the result of BifItem() as well as in the Describe() output.
	 */
	virtual bif_item_list CustomBifItems() ;

	/**
	 * Internal function adding an entry point for registering
	 * auto-generated BiFs.
	 */
	void AddBifInitFunction(bif_init_func c);

private:
	typedef std::list<bif_init_func> bif_init_func_list;

	const char* name;
	const char* description;
	int version;
	int api_version;

	component_list components;
	bif_item_list bif_items;
	bif_init_func_list bif_inits;
};

}

#endif
