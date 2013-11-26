// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include <list>
#include <string>

#include "Macros.h"

class ODesc;
class Func;
class Event;

namespace plugin  {

class Manager;
class Component;

/**
 * Hook types that a plugin may define. Each label maps to the corresponding
 * virtual method in \a Plugin.
 */
enum HookType {
	// Note: when changing this table, update hook_name() in Plugin.cc.
	HOOK_LOAD_FILE,
	HOOK_CALL_FUNCTION,
	HOOK_QUEUE_EVENT,
	HOOK_DRAIN_EVENTS,
	HOOK_UPDATE_NETWORK_TIME,
	// End marker.
	NUM_HOOKS,
};

/**
 * A class describing an item defined in \c *.bif file.
 */
class BifItem {
public:
	/**
	 * Type of the item.
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
	BifItem(const char* id, Type type);

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
 * Plugins encapsulate functionality that extends one or more of Bro's major
 * subsystems, such as analysis of a specific protocol, or logging output in
 * a particular format. A plugin acts a logical container that can provide a
 * set of different functionality. Specifically, it may:
 *
 * - Provide one or more \a components implementing functionality. For
 *   example, a RPC plugin could provide analyzer for set of related
 *   protocols (RPC, NFS, etc.), each of which would be a separate component.
 *   Likewise, a SQLite plugin could provide both a writer and reader
 *   component. In addition to components, a plugin can also provide of
 *   script-level elements defined in *.bif files.
 *
 * - Provide BiF elements (functions, events, types, globals).
 *
 * - Provide hooks (aka callbacks) into Bro's core processing to inject
 *   and/or alter functionality.
 *
 * Note that a plugin needs to explicitly register all the functionality it
 * provides. For components, it needs to call AddComponent(); for BiFs
 * AddBifItem(); and for hooks EnableHook() and then also implemennt the
 * corresponding virtual method).
 *
 */
class Plugin {
public:
	typedef std::list<Component *> component_list;
	typedef std::list<BifItem> bif_item_list;
	typedef std::list<std::pair<HookType, int> > hook_list;
	typedef std::list<std::pair<const char*, int> > bif_init_func_result;
	typedef void (*bif_init_func)(Plugin *);

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
	 * For dynamic plugins, returns the base directory from which it was
	 * loaded. For static plugins, returns null.
	 **/
	const char* PluginDirectory() const;

	/**
	 * For dynamic plugins, returns the full path to the shared library
	 * from which it was loaded. For static plugins, returns null.
	 **/
	const char* PluginPath() const;

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
	 * custom tasks at shutdown.  This can be overridden by derived
	 * classes; they must however call the parent's implementation.
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

	/**
	 * Registers an individual BiF that the plugin defines.  The
	 * information is for informational purpuses only and will show up in
	 * the result of BifItems() as well as in the Describe() output.
	 * Another way to add this information is via overriding
	 * CustomBifItems().
	 *
	 * \todo Do we need both this an CustomBifItems()?
	 *
	 * @param name The name of the BiF item.
	 *
	 * @param type The item's type.
	 */
	void AddBifItem(const char* name, BifItem::Type type);

	/**
	 * Adds a file to the list of files that Bro loads at startup. This
	 * will normally be a Bro script, but it passes through the plugin
	 * system as well to load files with other extensions as supported by
	 * any of the current plugins. In other words, calling this method is
	 * similar to given a file on the command line. Note that the file
	 * may be only queued for now, and actually loaded later.
	 *
	 * This method must not be called after InitPostScript().
	 *
	 * @param file The file to load. It will be searched along the standard paths.
	 *
	 * @return True if successful (which however may only mean
	 * "successfully queued").
	 */
	bool LoadBroFile(const char* file);

	/**
	 * Internal function adding an entry point for registering
	 * auto-generated BiFs.
	 */
	void __AddBifInitFunction(bif_init_func c);

protected:
	friend class Manager;

	/**
	 * Registers and activates a component.
	 *
	 * @param c The component. The method takes ownership.
	 */
	void AddComponent(Component* c);

	/**
	 * Enables a hook. The corresponding virtual method will now be
	 * called as Bro's processing proceeds. Note that enabling hooks can
	 * have performance impaxct as many trigger frequently inside Bro's
	 * main processing path.
	 *
	 * Note that hooks may be enabled/disabled dynamically at any time,
	 * the output of Bro's \c -NN option will only reflect that state at
	 * startup time; hence usually one should call this for a plugin's
	 * hooks in either the plugin's ctor or in InitPreScript(). For
	 * consistency with other parts of the API, there's a macro
	 * PLUGIN_ENABLE_HOOK for use inside the ctor.
	 *
	 * @param hook The hook to enable.
	 *
	 * @param priority If multiple plugins enable the same hook, their
	 * priorities determine the order in which they'll be executed, from
	 * highest to lowest. If two plugins specify the same priority, order
	 * is undefined.
	 */
	void EnableHook(HookType hook, int priority = 0);

	/**
	 * Disables a hook. Bro will no longer call the corresponding virtual
	 * method.
	 *
	 * @param hook The hook to disable.
	 */
	void DisableHook(HookType hook);

	/**
	 * Returns a list of hooks that are currently enabled for the plugin,
	 * along with their priorities.
	 */
	hook_list EnabledHooks() const;

	/**
	 * Virtual method that can be overriden by derived class to provide
	 * information about further script-level elements that the plugin
	 * provides on its own, i.e., outside of the standard mechanism
	 * processing *.bif files automatically. The returned information is
	 * for informational purposes only and will show up in the result of
	 * BifItems() as well as in the Describe() output.
	 *
	 * \todo Do we need both this an AddBifItem()?
	 */
	virtual bif_item_list CustomBifItems() const;

	// Hook functions.

	/**
	 * Hook into loading input files. This method will be called between
	 * InitPreScript() and InitPostScript(), but with no further order or
	 * timing guaranteed. It will be called once for each input file Bro
	 * is about to load, either given on the command line or via @load
	 * script directives. The hook can take over the file, in which case
	 * Bro not further process it otherwise.
	 *
	 * @return 1 if the plugin took over the file and loaded it
	 * successfully; 0 if the plugin took over the file but had trouble
	 * loading it (Bro will abort in this case, the plugin should have
	 * printed an error message); and -1 if the plugin wasn't interested
	 * in the file at all.
	 */
	virtual int HookLoadFile(const char* file);

	/**
	 * Hook into executing a script-level function/event/hook. Whenever
	 * the script interpreter is about to execution a function, it first
	 * gives all plugins with this hook enabled a chance to handle the
	 * call (in the order of their priorities). A plugin can either just
	 * inspect the call, or replace it (i.e., prevent the interpreter
	 * from executing it). In the latter case it must provide a matching
	 * return value.
	 *
	 * The default implementation does never handle the call in any way.
	 *
	 * @param func The function being called.
	 *
	 * @param args The function arguments. The method can modify the list
	 * in place long as it ensures matching types and correct reference
	 * counting.
	 *
	 * @return If the plugin handled the call, a +1 Val with the result
	 * value to pass back to the interpreter (for void functions and
	 * events any \a Val is fine; it will be ignored; best to use a \c
	 * TYPE_ANY). If the plugin did not handle the call, it must return
	 * null.
	 */
	virtual Val* HookCallFunction(const Func* func, val_list* args);

	/**
	 * Hook into raising events. Whenever the script interpreter is about
	 * to queue an event for later execution, it first gives all plugins
	 * with this hook enabled a chance to handle the queuing otherwise
	 * (in the order of their priorities). A plugin can either just
	 * inspect the event, or take it over (i.e., prevent the interpreter
	 * from queuing it it).
	 *
	 * The default implementation does never handle the queuing in any
	 * way.
	 *
	 * @param event The even to be queued. The method can modify it in in
	 * place long as it ensures matching types and correct reference
	 * counting.
	 *
	 * @return True if the plugin took charge of the event; in that case
	 * it must have assumed ownership of the event and the intpreter will
	 * not do anything further with it. False otherwise.
	 */
	virtual bool HookQueueEvent(Event* event);

	/**
	 * Hook intp event queue draining. This method will be called
	 * whenever the event manager is draining its queue.
	 */
	virtual void HookDrainEvents();

	/**
	 * Hook for updates to network time. This method will be called
	 * whenever network time is advanced.
	 *
	 * @param networkt_time The new network time.
	 */
	virtual void HookUpdateNetworkTime(double network_time);

	// Methods that are used internally primarily.

	/**
	 * Sets the plugins name.
	 *
	 * This is used primarily internally; plugin code should pass the
	 * name via the BRO_PLUGIN_BEGIN macro instead.
	 *
	 * @param name The name. Makes a copy internally.
	 */
	void SetName(const char* name);

	/**
	 * Sets the plugin's textual description.
	 *
	 * This is used primarily internally; plugin code should pass the
	 * name via the BRO_PLUGIN_DESCRIPTION macro instead.
	 *
	 * @param name The description. Makes a copy internally.
	 */
	void SetDescription(const char* descr);

	/**
	 * Sets the plugin's version.
	 *
	 * This is used primarily internally; plugin code should pass the
	 * name via the BRO_PLUGIN_VERSION macro instead.
	 *
	 * @param version The version.
	 */
	void SetVersion(int version);

	/**
	 * Sets the API version the plugin requires.
	 * BRO_PLUGIN_VERSION_BUILTIN indicates that it's a plugin linked in
	 * statically.
	 *
	 * This is used primarily internally; plugins automatically set
	 * either API version of the Bro they are compiled dynamically for,
	 * or BRO_PLUGIN_VERSION_BUILTIN if they are linked in statically.
	 *
	 * @param version The version.
	 */
	void SetAPIVersion(int version);

	/**
	 * Marks the plugin as statically or dynamically linked.
	 *
	 * This is used primarily internally; plugins automatically set this
	 * based on which way they are compiled.
	 *
	 * @param dynamic True if this is a dynamically linked plugin.
	 */
	void SetDynamicPlugin(bool dynamic);

	/**
	 * Sets the base directory and shared library path from which the
	 * plugin was loaded.
	 *
	 * This is used primarily internally; plugins will have there
	 * location set automatically.
	 *
	 * @param dir The plugin directory. The functions makes an internal
	 * copy of string.
	 *
	 * @param sopath The full path the shared library loaded. The
	 * functions makes an internal copy of string.
	 */
	void SetPluginLocation(const char* dir, const char* sopath);

private:
	/**
	 * Initializes the BiF items added with AddBifItem(). Internal method
	 * that will be called by the manager at the right time.
	 */
	void InitBifs();

	typedef std::list<bif_init_func> bif_init_func_list;

	const char* name;
	const char* description;
	const char* base_dir;
	const char* sopath;
	int version;
	int api_version;
	bool dynamic;

	component_list components;
	bif_item_list bif_items;
	bif_init_func_list bif_inits;
};

}

#endif
