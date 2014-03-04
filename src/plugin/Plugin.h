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
	typedef std::list<std::pair<const char*, int> > bif_init_func_result;
	typedef void (*bif_init_func)(Plugin *);

	/**
	 * Type of a plugin. Plugin types are set implicitly by deriving from
	 * the corresponding base class. */
	enum Type {
		/**
		 * A standard plugin. This is the type for all plugins
		 * derived directly from \a Plugin. */
		STANDARD,

		/**
		 * An interpreter plugin. These plugins get hooked into the
		 * script interpreter and can modify, or even replace, its
		 * execution of Bro script code. To create an interpreter
		 * plugin, derive from \aInterpreterPlugin.
		 */
		INTERPRETER
	};

	/**
	 * Constructor.
	 */
	Plugin();

	/**
	 * Destructor.
	 */
	virtual ~Plugin();

	/**
	 * Returns the type of the plugin.
	 */
	virtual Type PluginType() const;

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
	 * Returns a colon-separated list of file extensions the plugin handles.
	 */
	const char* FileExtensions() const;

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

	/**
	 * Registering an individual BiF that the plugin defines.  The
	 * information is for informational purpuses only and will show up in
	 * the result of BifItems() as well as in the Describe() output.
	 * Another way to add this information is via overriding
	 * CustomBifItems().
	 *
	 * @param name The name of the BiF item.
	 *
	 * @param type The item's type.
	 */
	void AddBifItem(const char* name, BifItem::Type type);

	/**
	 * Adds a file to the list of files Bro loads at startup. This will
	 * normally be a Bro script, but it passes through the plugin system
	 * as well to load files with other extensions as supported by any of
	 * the current plugins. In other words, calling this method is
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

protected:
	friend class Manager;

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
	 * Reports the extensions of input files the plugin handles. If Bro
	 * wants to load a file with one of these extensions it will pass
	 * them to LoadFile() and then then ignore otherwise.
	 *
	 * ext: A list of colon-separated file extensions the plugin handles.
	 */
	void SetFileExtensions(const char* ext);

	/**
	 * Sets the base directory and shared library path from which the
	 * plugin was loaded. This should be called only from the manager for
	 * dynamic plugins.
	 *
	 * @param dir The plugin directory. The functions makes an internal
	 * copy of string.
	 *
	 * @param sopath The full path the shared library loaded. The
	 * functions makes an internal copy of string.
	 */
	void SetPluginLocation(const char* dir, const char* sopath);

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
	 * Virtual method that can be overriden by derived class to load
	 * files with extensions reported via SetFileExtension().
	 *
	 * This method will be called between InitPreScript() and
	 * InitPostScript(), but with no further order or timing guaranteed.
	 * It will be called once for each file encountered with of the
	 * specificed extensions (i.e., duplicates are filtered out
	 * automatically).
	 *
	 * @return True if the file was loaded successfuly, false if not. Bro
	 * will abort in the latter case.
	 */
	virtual bool LoadFile(const char* file);

	/**
	 * Initializes the BiF items added with AddBifItem(). Internal method
	 * that will be called by the manager at the right time.
	 */
	void InitBifs();

	/**
	 * Internal function adding an entry point for registering
	 * auto-generated BiFs.
	 */
	void __AddBifInitFunction(bif_init_func c);

private:
	typedef std::list<bif_init_func> bif_init_func_list;

	const char* name;
	const char* description;
	const char* base_dir;
	const char* sopath;
	const char* extensions;
	int version;
	int api_version;
	bool dynamic;

	component_list components;
	bif_item_list bif_items;
	bif_init_func_list bif_inits;
};

/**
 * Class for hooking into script execution. An interpreter plugin can do
 * everything a normal plugin can, yet will also be interfaced to the script
 * interpreter for learning about, modidying, or potentially replacing
 * standard functionality.
 */
class InterpreterPlugin : public Plugin {
public:
	/**
	 * Constructor.
	 *
	 * @param priority Imposes an order on InterpreterPlugins in which
	 * they'll be chained. The higher the prioritu, the earlier a plugin
	 * is called when the interpreter goes through the chain. */
	InterpreterPlugin(int priority);

	/**
	 * Destructor.
	 */
	virtual ~InterpreterPlugin();

	/**
	 * Returns the plugins priority.
	 */
	int Priority() const;

	/**
	 * Callback for executing a function/event/hook. Whenever the script
	 * interpreter is about to execution a function, it first gives all
	 * InterpreterPlugins a chance to handle the call (in the order of their
	 * priorities). A plugin can either just inspect the call, or replace it
	 * (i.e., prevent the interpreter from executing it). In the latter case
	 * it must provide a matching return value.
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
	virtual Val* CallFunction(const Func* func, val_list* args);

    /**
     * Callback for raising an event. Whenever the script interpreter is
     * about to queue an event for later execution, it first gives all
     * InterpreterPlugins a chance to handle the queuing otherwise (in the
     * order of their priorities). A plugin can either just inspect the
     * event, or take it over (i.e., prevent the interpreter from queuing it
     * it).
     *
	 * The default implementation does never handle the queuing in any way.
     *
     * @param event The even to be queued. The method can modify it in in
     * place long as it ensures matching types and correct reference
     * counting.
     *
     * @return True if the plugin took charge of the event; in that case it
     * must have assumed ownership of the event and the intpreter will not do
     * anything further with it. False otherwise.
	 *
     */
	virtual bool QueueEvent(Event* event);

	/**
	 * Callback for updates in network time. This method will be called
	 * whenever network time is advanced.
	 *
	 * @param networkt_time The new network time.
	 */
	virtual void UpdateNetworkTime(double network_time);

	/**
	 * Callback for event queue draining. This method will be called
	 * whenever the event manager has drained it queue.
	 */
	virtual void DrainEvents();

	/**
	 * Callback for instantiation of a new connection.
	 */
	virtual void NewConnection(const Connection* c);

	/**
	 * Callback for an upcoming removal of a connection.
	 */
	virtual void ConnectionStateRemove(const Connection* c);

	/**
	 * Disables interpreter hooking. The functionality of the Plugin base
	 * class remains available.
	 */
	void DisableInterpreterPlugin() const;

	/**
	 * Mark interest in an event. The event will then be raised, and
	 * hence passed to the plugin, even if there no handler defined.
	 */
	void RequestEvent(EventHandlerPtr handler);

	// Overridden from base class.
	virtual Type PluginType() const;

private:
	int priority;

};

}

#endif
