// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include <list>
#include <string>

#include "Macros.h"

class ODesc;

namespace plugin  {

class Manager;
class Component;

/**
 * A class describing an item defined in \c *.bif file.
 */
class BifItem {
public:
	/**
	 * Type of the item.
	 *
	 * The values here must match the integers that \c bifcl generated.
	 */
	enum Type { FUNCTION = 1, EVENT = 2, CONSTANT = 3, GLOBAL = 4, TYPE = 5 };

	/**
	 * Constructor.
	 *
	 * @param id The script-level name of the item. This should be fully
	 * qualified.
	 *
	 * @param type The type of the item.
	 */
	BifItem(const std::string& id, Type type);

	/**
	 * Copy constructor.
	 */
	BifItem(const BifItem& other);

	/**
	 * Assigment operator.
	 */
	BifItem& operator=(const BifItem& other);

	/**
	 * Destructor.
	 */
	~BifItem();

	/**
	 * Returns the script-level ID as passed into the constructor.
	 */
	const char* GetID() const	{ return id; }

	/**
	 * Returns the type as passed into the constructor.
	 */
	Type GetType() const	{ return type; }

private:
	const char* id;
	Type type;
};

/**
 * Base class for all plugins.
 *
 * Plugins encapsulate functionality that extends one of Bro's major
 * subsystems, such as analysis of a specific protocol, or logging output in
 * a particular format. A plugin is a logical container that can provide one
 * or more \a components implementing functionality. For example, a RPC
 * plugin could provide analyzer for set of related protocols (RPC, NFS,
 * etc.), each of which would be a separate component. Likewise, a SQLite
 * plugin could provide both a writer and reader component. In addition to
 * components, a plugin can also provide of script-level elements defined in
 * *.bif files.
 *
 * Currently, all plugins are compiled statically into the final Bro binary.
 * Later, we will extend the infrastructure to also support plugins loaded
 * dynamically as shared libraries.
 */
class Plugin {
public:
	typedef std::list<Component *> component_list;
	typedef std::list<BifItem> bif_item_list;

	/**
	 * Constructor.
	 */
	Plugin();

	/**
	 * Destructor.
	 */
	virtual ~Plugin();

	/**
	 * Returns the name of the plugin.
	 */
	const char* Name() const;

	/**
	 * Returns a short textual description of the plugin, if provided.
	 */
	const char* Description() const;

	/**
	 * Returns the version of the plugin. Version are only meaningful for
	 * dynamically compiled plugins; for statically compiled ones, this
	 * will always return 0.
	 */
	int Version() const;

	/**
	 * Returns true if this is a dynamically linked in plugin.
	 */
	bool DynamicPlugin() const;

	/**
	 * Returns the internal API version that this plugin relies on. Only
	 * plugins that match Bro's current API version may be used. For
	 * statically compiled plugins this is automatically the case, but
	 * dynamically loaded plugins may cause a mismatch if they were
	 * compiled for a different Bro version.
	 */
	int APIVersion() const;

	/**
	 * Returns a list of all components the plugin provides.
	 */
	component_list Components() const;

	/**
	 * Returns a list of all BiF items that the plugin provides. This
	 * must be called only after InitBif() has been executed.
	 */
	bif_item_list BifItems() const;

	/**
	 * First-stage initialization of the plugin called early during Bro's
	 * startup, before scripts are parsed. This can be overridden by
	 * derived classes; they must however call the parent's
	 * implementation.
	 */
	virtual void InitPreScript();

	/**
	 * Second-stage initialization of the plugin called late during Bro's
	 * startup, after scripts are parsed. This can be overridden by
	 * derived classes; they must however call the parent's
	 * implementation.
	 */
	virtual void InitPostScript();

	/**
	 * Finalizer method that derived classes can override for performing
	 * custom tasks at shutdown. Implementation must call the parent's
	 * version.
	 */
	virtual void Done();

	/**
	 * Returns a textual description of the plugin.
	 *
	 * @param d Description object to use for rendering. If "short mode"
	 * is disabled, the rendering will include a list of all components
	 * and BiF items.
	 */
	void Describe(ODesc* d) const;

protected:
	typedef std::list<std::pair<const char*, int> > bif_init_func_result;
	typedef bif_init_func_result (*bif_init_func)();

	/**
	 * Sets the plugins name.
	 *
	 * @param name The name. Makes a copy internally.
	 */
	void SetName(const char* name);

	/**
	 * Sets the plugin's textual description.
	 *
	 * @param name The description. Makes a copy internally.
	 */
	void SetDescription(const char* descr);

	/**
	 * Sets the plugin's version.
	 *
	 * @param version The version.
	 */
	void SetVersion(int version);

	/**
	 * Sets the API version the plugin requires.
	 * BRO_PLUGIN_VERSION_BUILTIN indicates that it's a plugin linked in
	 * statically.
	 */
	void SetAPIVersion(int version);

	/**
	 * Marks the plugin as statically or dynamically linked.
	 *
	 * @param dynamic True if this is a dynamically linked plugin.
	 */
	void SetDynamicPlugin(bool dynamic);

	/**
	 * Takes ownership.
	 */
	void AddComponent(Component* c);

	/**
	 * Virtual method that can be overriden by derived class to provide
	 * information about further script-level elements that the plugins
	 * provides on its own, i.e., outside of the standard mechanism
	 * processing *.bif files automatically. The returned information is
	 * for informational purpuses only and will show up in the result of
	 * BifItems() as well as in the Describe() output.
	 */
	virtual bif_item_list CustomBifItems() const;

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
	bool dynamic;

	component_list components;
	bif_item_list bif_items;
	bif_init_func_list bif_inits;
};

}

#endif
