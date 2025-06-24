// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <functional>
#include <list>
#include <optional>
#include <string>
#include <utility>

#include "zeek/ZeekArgs.h"
#include "zeek/logging/WriterBackend.h"

// Avoid ccache busting of Plugin.h for internal plugins by
// only including zeek/zeek-version.h if we're building an
// external plugin. The define gets set in the CMakeLists.txt file
// for the Zeek::Internal target, which only exists when
// building Zeek itself.
#ifndef ZEEK_PLUGIN_SKIP_VERSION_CHECK
#include "zeek/zeek-version.h"
#define ZEEK_PLUGIN_ZEEK_VERSION ZEEK_VERSION_FUNCTION
#endif

namespace zeek::threading {
struct Field;
}

namespace zeek {

#ifdef _MSC_VER
#undef VOID
#endif

// Increase this when making incompatible changes to the plugin API. Note
// that the constant is never used in C code. It's picked up on by CMake.
constexpr int PLUGIN_API_VERSION = 7;

class ODesc;
class Event;
class Func;
class Obj;
class Packet;

template<class T>
class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;

namespace threading {
struct Field;
}
namespace detail {
class Frame;
}

namespace cluster {
class Backend;

namespace detail {
class Event;
}
} // namespace cluster

namespace plugin {

class Manager;
class Component;
class Plugin;

/**
 * Hook types that a plugin may define. Each label maps to the corresponding
 * virtual method in \a Plugin.
 */
enum HookType : uint8_t {
    // Note: when changing this table, update hook_name() in Plugin.cc.
    HOOK_LOAD_FILE,           //< Activates Plugin::HookLoadFile().
    HOOK_LOAD_FILE_EXT,       //< Activates Plugin::HookLoadFileExtended().
    HOOK_CALL_FUNCTION,       //< Activates Plugin::HookCallFunction().
    HOOK_QUEUE_EVENT,         //< Activates Plugin::HookQueueEvent().
    HOOK_DRAIN_EVENTS,        //< Activates Plugin::HookDrainEvents().
    HOOK_UPDATE_NETWORK_TIME, //< Activates Plugin::HookUpdateNetworkTime().
    HOOK_SETUP_ANALYZER_TREE, //< Activates Plugin::HookAddToAnalyzerTree().
    HOOK_LOG_INIT,            //< Activates Plugin::HookLogInit().
    HOOK_LOG_WRITE,           //< Activates Plugin::HookLogWrite().
    HOOK_REPORTER,            //< Activates Plugin::HookReporter().
    HOOK_UNPROCESSED_PACKET,  //<Activates Plugin::HookUnprocessedPacket().
    HOOK_OBJ_DTOR,            //< Activates Plugin::HookObjDtor().
    HOOK_PUBLISH_EVENT,       //< Activates Plugin::HookPublishEvent().

    // Meta hooks.
    META_HOOK_PRE,  //< Activates Plugin::MetaHookPre().
    META_HOOK_POST, //< Activates Plugin::MetaHookPost().

    // End marker.
    NUM_HOOKS,
};

/**
 * Converts a hook type into a readable hook name.
 */
extern const char* hook_name(HookType h);

/**
 * Helper class to capture a plugin's version.
 * */
struct VersionNumber {
    int major = -1; //< Major version number.
    int minor = -1; //< Minor version number.
    int patch = 0;  //< Patch version number (available since Zeek 3.0).

    /**
     *  Returns true if the version is set to a non-negative value.
     */
    explicit operator bool() const { return major >= 0 && minor >= 0 && patch >= 0; }
};

/**
 * A class defining a plugin's static configuration parameters.
 */
class Configuration {
public:
    std::string name = "";        //< The plugin's name, including a namespace. Mandatory.
    std::string description = ""; //< A short textual description of the plugin. Mandatory.
    VersionNumber version;        //< THe plugin's version. Optional.

    // We force this to inline so that the API version gets hardcoded
    // into the external plugin. (Technically, it's not a "force", just a
    // strong hint.). The attribute seems generally available.
    inline Configuration() __attribute__((always_inline)) {
// Only bake in a ZEEK_PLUGIN_ZEEK_VERSION reference into external plugins. The
// internal ones are in the same binary so the runtime link check shouldn't be
// needed and we can avoid ccache busting. The define gets set in the
// CMakeLists.txt file for the Zeek::Internal target, which only exists when
// building Zeek itself.
#ifndef ZEEK_PLUGIN_SKIP_VERSION_CHECK
        zeek_version = ZEEK_PLUGIN_ZEEK_VERSION;
#endif
    }

    Configuration(Configuration&& c) noexcept {
        zeek_version = std::move(c.zeek_version);

        name = std::move(c.name);
        description = std::move(c.description);
        version = c.version;
    }

    Configuration(const Configuration& c) {
        zeek_version = c.zeek_version;

        name = c.name;
        description = c.description;
        version = c.version;
    }

    Configuration& operator=(Configuration&& c) noexcept {
        zeek_version = std::move(c.zeek_version);

        name = std::move(c.name);
        description = std::move(c.description);
        version = c.version;

        return *this;
    }

    Configuration& operator=(const Configuration& c) {
        zeek_version = c.zeek_version;

        name = c.name;
        description = c.description;
        version = c.version;

        return *this;
    }

    ~Configuration() {}

    /**
     * One can assign ZEEK_PLUGIN_ZEEK_VERSION to this to catch
     * version mismatches at link(!) time.
     */
    std::function<const char*()> zeek_version;

private:
    friend class Plugin;
};

/**
 * A class describing an item defined in \c *.bif file.
 */
class BifItem final {
public:
    /**
     * Type of the item.
     */
    enum Type : uint8_t {
        FUNCTION = 1,
        EVENT = 2,
        CONSTANT = 3,
        GLOBAL = 4,
        TYPE = 5,
    };

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
     * Assignment operator.
     */
    BifItem& operator=(const BifItem& other);

    /**
     * Destructor.
     */
    ~BifItem() = default;

    /**
     * Returns the script-level ID as passed into the constructor.
     */
    const std::string& GetID() const { return id; }

    /**
     * Returns the type as passed into the constructor.
     */
    Type GetType() const { return type; }

private:
    std::string id;
    Type type;
};

/**
 * A class encapsulating an event argument to then pass along with a meta hook.
 */
class HookArgument {
public:
    /**
     * Type of the argument.
     */
    enum Type : uint8_t {
        BOOL,
        DOUBLE,
        EVENT,
        FRAME,
        FUNC,
        FUNC_RESULT,
        INT,
        STRING,
        VAL,
        VAL_LIST,
        VOID,
        VOIDP,
        WRITER_INFO,
        CONN,
        THREAD_FIELDS,
        LOCATION,
        ARG_LIST,
        INPUT_FILE,
        PACKET,
        CLUSTER_BACKEND,
        CLUSTER_EVENT,
    };

    /**
     * Default constructor initialized the argument with type VOID.
     */
    HookArgument() { type = VOID; }

    /**
     * Constructor with a boolean argument.
     */
    explicit HookArgument(bool a) {
        type = BOOL;
        arg.bool_ = a;
    }

    /**
     * Constructor with a double argument.
     */
    explicit HookArgument(double a) {
        type = DOUBLE;
        arg.double_ = a;
    }

    /**
     * Constructor with an event argument.
     */
    explicit HookArgument(const Event* a) {
        type = EVENT;
        arg.event = a;
    }

    /**
     * Constructor with an connection argument.
     */
    explicit HookArgument(const Connection* c) {
        type = CONN;
        arg.conn = c;
    }

    /**
     * Constructor with a function argument.
     */
    explicit HookArgument(const Func* a) {
        type = FUNC;
        arg.func = a;
    }

    /**
     * Constructor with an integer  argument.
     */
    explicit HookArgument(int a) {
        type = INT;
        arg.int_ = a;
    }

    /**
     * Constructor with a string argument.
     */
    explicit HookArgument(const std::string& a) {
        type = STRING;
        arg_string = a;
    }

    /**
     * Constructor with a Zeek value argument.
     */
    explicit HookArgument(const Val* a) {
        type = VAL;
        arg.val = a;
    }

    /**
     * Constructor with a list of Zeek values argument.
     */
    explicit HookArgument(const ValPList* a) {
        type = VAL_LIST;
        arg.vals = a;
    }

    /**
     * Constructor with a void pointer argument.
     */
    explicit HookArgument(void* p) {
        type = VOIDP;
        arg.voidp = p;
    }

    /**
     * Constructor with a function result argument.
     */
    explicit HookArgument(std::pair<bool, Val*> fresult) {
        type = FUNC_RESULT;
        func_result = fresult;
    }

    /**
     * Constructor with a Frame argument.
     */
    explicit HookArgument(zeek::detail::Frame* f) {
        type = FRAME;
        arg.frame = f;
    }

    /**
     * Constructor with a WriterInfo argument.
     */
    explicit HookArgument(const logging::WriterBackend::WriterInfo* i) {
        type = WRITER_INFO;
        arg.winfo = i;
    }

    /**
     * Constructor with a threading field argument.
     */
    explicit HookArgument(const std::pair<int, const threading::Field* const*> fpair) {
        type = THREAD_FIELDS;
        tfields = fpair;
    }

    /**
     * Constructor with a location argument.
     */
    explicit HookArgument(const zeek::detail::Location* location) {
        type = LOCATION;
        arg.loc = location;
    }

    /**
     * Constructor with a zeek::Args argument.
     */
    explicit HookArgument(const Args* args) {
        type = ARG_LIST;
        arg.args = args;
    }

    /**
     * Constructor with HookLoadFileExtended result describing an input file.
     */
    explicit HookArgument(std::pair<int, std::optional<std::string>> file) {
        type = INPUT_FILE;
        input_file = std::move(file);
    }

    /**
     * Returns the value for a zeek::Packet* argument. The argument's type must
     * Constructor with a zeek::Packet* argument.
     */
    explicit HookArgument(const Packet* packet) {
        type = PACKET;
        arg.packet = packet;
    }

    /**
     * Constructor with cluster backend argument.
     */
    explicit HookArgument(zeek::cluster::Backend* backend) {
        type = CLUSTER_BACKEND;
        arg.cluster_backend = backend;
    }

    /**
     * Constructor with cluster event argument.
     */
    explicit HookArgument(zeek::cluster::detail::Event* event) {
        type = CLUSTER_EVENT;
        arg.cluster_event = event;
    }

    /**
     * Returns the value for a boolean argument. The argument's type must
     * match accordingly.
     */
    bool AsBool() const {
        assert(type == BOOL);
        return arg.bool_;
    }

    /**
     * Returns the value for a double argument. The argument's type must
     * match accordingly.
     */
    double AsDouble() const {
        assert(type == DOUBLE);
        return arg.double_;
    }

    /**
     * Returns the value for an event argument. The argument's type must
     * match accordingly.
     */
    const Event* AsEvent() const {
        assert(type == EVENT);
        return arg.event;
    }

    /**
     * Returns the value for an connection argument. The argument's type must
     * match accordingly.
     */
    const Connection* AsConnection() const {
        assert(type == CONN);
        return arg.conn;
    }

    /**
     * Returns the value for a function argument. The argument's type must
     * match accordingly.
     */
    const Func* AsFunc() const {
        assert(type == FUNC);
        return arg.func;
    }

    /**
     * Returns the value for an integer argument. The argument's type must
     * match accordingly.
     */
    double AsInt() const {
        assert(type == INT);
        return arg.int_;
    }

    /**
     * Returns the value for a string argument. The argument's type must
     * match accordingly.
     */
    const std::string& AsString() const {
        assert(type == STRING);
        return arg_string;
    }

    /**
     * Returns the value for a Zeek value argument. The argument's type must
     * match accordingly.
     */
    const Val* AsVal() const {
        assert(type == VAL);
        return arg.val;
    }

    /**
     * Returns the value for a Zeek wrapped value argument.  The argument's type must
     * match accordingly.
     */
    const std::pair<bool, Val*> AsFuncResult() const {
        assert(type == FUNC_RESULT);
        return func_result;
    }

    /**
     * Returns the value for a Zeek frame argument.  The argument's type must
     * match accordingly.
     */
    const zeek::detail::Frame* AsFrame() const {
        assert(type == FRAME);
        return arg.frame;
    }

    /**
     * Returns the value for a logging WriterInfo argument.  The argument's type must
     * match accordingly.
     */
    const logging::WriterBackend::WriterInfo* AsWriterInfo() const {
        assert(type == WRITER_INFO);
        return arg.winfo;
    }

    /**
     * Returns the value for a threading fields argument.  The argument's type must
     * match accordingly.
     */
    const std::pair<int, const threading::Field* const*> AsThreadFields() const {
        assert(type == THREAD_FIELDS);
        return tfields;
    }

    /**
     * Returns the value for a list of Zeek values argument. The argument's type must
     * match accordingly.
     */
    const ValPList* AsValList() const {
        assert(type == VAL_LIST);
        return arg.vals;
    }

    /**
     * Returns the value as a Args.
     */
    const Args* AsArgList() const {
        assert(type == ARG_LIST);
        return arg.args;
    }

    /**
     * Returns the value for a void pointer argument. The argument's type
     * must match accordingly.
     */
    const void* AsVoidPtr() const {
        assert(type == VOIDP);
        return arg.voidp;
    }

    /**
     * Returns the value for a Packet pointer argument. The argument's type
     * must match accordingly.
     */
    const Packet* AsPacket() const {
        assert(type == PACKET);
        return arg.packet;
    }

    /**
     * Returns the value for a cluster backend argument.
     */
    const zeek::cluster::Backend* AsClusterBackend() const {
        assert(type == CLUSTER_EVENT);
        return arg.cluster_backend;
    }

    /**
     * Returns the value for a cluster event argument.
     */
    const zeek::cluster::detail::Event* AsClusterEvent() const {
        assert(type == CLUSTER_EVENT);
        return arg.cluster_event;
    }

    /**
     * Returns the argument's type.
     */
    Type GetType() const { return type; }

    /**
     * Returns a textual representation of the argument.
     *
     * @param d Description object to use for rendering.
     */
    void Describe(ODesc* d) const;

private:
    Type type;
    union {
        bool bool_;
        double double_;
        const Event* event;
        const Connection* conn;
        const Func* func;
        const zeek::detail::Frame* frame;
        int int_;
        const Val* val;
        const ValPList* vals;
        const Args* args;
        const void* voidp;
        const logging::WriterBackend::WriterInfo* winfo;
        const zeek::detail::Location* loc;
        const Packet* packet;
        const cluster::Backend* cluster_backend;
        const cluster::detail::Event* cluster_event;
    } arg;

    // Outside union because these have dtors.
    std::pair<bool, Val*> func_result;
    std::pair<int, const threading::Field* const*> tfields;
    std::string arg_string;
    std::pair<int, std::optional<std::string>> input_file;
};

using HookArgumentList = std::list<HookArgument>;

/**
 * Base class for all plugins.
 *
 * Plugins encapsulate functionality that extends one or more of Zeek's major
 * subsystems, such as analysis of a specific protocol, or logging output in
 * a particular format. A plugin acts a logical container that can provide a
 * set of functionality. Specifically, it may:
 *
 * - Provide one or more \a components implementing functionality. For
 *   example, a RPC plugin could provide analyzer for set of related
 *   protocols (RPC, NFS, etc.), each of which would be a separate component.
 *   Likewise, an SQLite plugin could provide both a writer and reader
 *   component.
 *
 * - Provide BiF elements (functions, events, types, globals). Typically
 *   they'll be defined in *.bif files, but a plugin can also create them
 *   internally.
 *
 * - Provide hooks (aka callbacks) into Zeek's core processing to inject
 *   and/or alter functionality.
 *
 * A plugin needs to explicitly register all the functionality it provides.
 * For components, it needs to call AddComponent(); for BiFs AddBifItem();
 * and for hooks EnableHook() and then also implement the corresponding
 * virtual methods.
 *
 */
class Plugin {
public:
    using component_list = std::list<Component*>;
    using bif_item_list = std::list<BifItem>;
    using hook_list = std::list<std::pair<HookType, int>>;

    /**
     * The different types of @loads supported by HookLoadFile.
     */
    enum LoadType : uint8_t { SCRIPT, SIGNATURES, PLUGIN };

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
    const std::string& Name() const;

    /**
     * Returns a short textual description of the plugin, if provided.
     */
    const std::string& Description() const;

    /**
     * Returns the version of the plugin. Versions are only meaningful
     * for dynamically compiled plugins; for statically compiled ones,
     * this will always return 0.
     */
    VersionNumber Version() const;

    /**
     * Returns true if this is a dynamically linked plugin.
     */
    bool DynamicPlugin() const;

    /**
     * For dynamic plugins, returns the base directory from which it was
     * loaded. For static plugins, returns an empty string.
     **/
    const std::string& PluginDirectory() const;

    /**
     * For dynamic plugins, returns the full path to the shared library
     * from which it was loaded. For static plugins, returns an empty
     * string.
     **/
    const std::string& PluginPath() const;

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
     * Returns a textual description of the plugin.
     *
     * @param d Description object to use for rendering. If "short mode"
     * is disabled, the rendering will include a list of all components
     * and BiF items.
     */
    void Describe(ODesc* d) const;

    /**
     * Registers an individual BiF that the plugin defines. The
     * information is for informational purposes only and will show up in
     * the result of BifItems() as well as in the Describe() output.
     * Another way to add this information is via overriding
     * CustomBifItems().
     *
     * Note that this method is rarely the right one to use. As it's for
     * informational purposes only, the plugin still needs to register
     * the BiF items themselves with the corresponding Zeek parts. Doing
     * so can be tricky, and it's recommend to instead define BiF items
     * in separate *.bif files that the plugin then pulls in. If defined
     * there, one does *not* need to call this method.
     *
     * @param name The name of the BiF item.
     *
     * @param type The item's type.
     */
    void AddBifItem(const std::string& name, BifItem::Type type);

    /**
     * Adds a file to the list of files that Zeek loads at startup. This
     * will normally be a Zeek script, but it passes through the plugin
     * system as well to load files with other extensions as supported by
     * any of the current plugins. In other words, calling this method is
     * similar to giving a file on the command line. Note that the file
     * may be only queued for now, and actually loaded later.
     *
     * This method must not be called after InitPostScript().
     *
     * @param file The file to load. It will be searched along the
     * standard paths.
     *
     * @return True if successful (which however may only mean
     * "successfully queued").
     */
    bool LoadZeekFile(const std::string& file);

protected:
    friend class Manager;

    /**
     * First-stage initialization of the plugin called early during Zeek's
     * startup, before scripts are parsed. This can be overridden by
     * derived classes; they must however call the parent's
     * implementation.
     */
    virtual void InitPreScript();

    /**
     * Second-stage initialization of the plugin called late during Zeek's
     * startup, after scripts are parsed. This can be overridden by
     * derived classes; they must however call the parent's
     * implementation.
     */
    virtual void InitPostScript();

    /**
     * Third-stage initialization of the plugin called just before enqueueing
     * zeek_init(), after script analysis and optimization completed.
     * This can be overridden by derived classes; they must however call the
     * parent's implementation.
     */
    virtual void InitPreExecution();

    /**
     * Finalizer method that derived classes can override for performing
     * custom tasks at shutdown.  This can be overridden by derived
     * classes; they must however call the parent's implementation.
     */
    virtual void Done();

    /**
     * Registers a component.
     *
     * @param c The component. The method takes ownership.
     */
    void AddComponent(Component* c);

    /**
     * Calls the Initialize() function of all components.
     */
    void InitializeComponents();

    /**
     * Enables a hook. The corresponding virtual method will now be
     * called as Zeek's processing proceeds. Note that enabling hooks can
     * have performance impact as many trigger frequently inside Zeek's
     * main processing path.
     *
     * Note that while hooks may be enabled/disabled dynamically at any
     * time, the output of Zeek's \c -NN option will only reflect their
     * state at startup time. Usually one should call this method for a
     * plugin's hooks in either the plugin's constructor or in
     * InitPreScript().
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
     * Disables a hook. Zeek will no longer call the corresponding virtual
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
     * Registers interest in an event, even if there's no handler for it.
     * Normally a plugin receives events through HookQueueEvent() only if Zeek
     * actually has code to execute for it. By calling this method, the
     * plugin tells Zeek to raise the event even if there's no corresponding
     * handler; it will then go into HookQueueEvent() just as any other.
     *
     * @param handler The event handler being interested in.
     */
    void RequestEvent(EventHandlerPtr handler);

    /**
     * Registers interest in the destruction of a Obj instance. When
     * Zeek's reference counting triggers the objects destructor to run,
     * \a HookObjDtor will be called.
     *
     * Note that this can get expensive if triggered for many objects.
     *
     * @param obj The object being interested in.
     */
    void RequestObjDtor(Obj* obj);

    // Hook functions.

    /**
     * Hook into loading input files. This method will be called between
     * InitPreScript() and InitPostScript(), but with no further order or
     * timing guaranteed. It will be called once for each input file Zeek
     * is about to load, either given on the command line or via @load
     * script directives. The hook can take over the file, in which case
     * Zeek will not further process it otherwise.
     *
     * @param type The type of load encountered: script load, signatures load,
     *             or plugin load.
     *
     * @param file The filename that was passed to @load. Only includes
     *             an extension if it was given in @load.
     *
     * @param resolved The file or directory name Zeek resolved from
     *                 the given path and is going to load. Empty string
     *                 if Zeek was not able to resolve a path.
     *
     * @return 1 if the plugin took over the file and loaded it
     * successfully; 0 if the plugin took over the file but had trouble
     * loading it (Zeek will abort in this case, and the plugin should
     * have printed an error message); and -1 if the plugin wasn't
     * interested in the file at all.
     */
    virtual int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved);

    /**
     * Hook into loading input files, with extended capabilities. This method
     * will be called between InitPreScript() and InitPostScript(), but with no
     * further order or timing guaranteed. It will be called once for each
     * input file Zeek is about to load, either given on the command line or via
     * @load script directives. The hook can take over the file, in which case
     * Zeek will not further process it otherwise. It can, alternatively, also
     * provide the file content as a string, which Zeek will then process just
     * as if it had read it from a file.
     *
     * @param type The type of load encountered: script load, signatures load,
     *             or plugin load.
     *
     * @param file The filename that was passed to @load. Only includes
     *             an extension if it was given in @load.
     *
     * @param resolved The file or directory name Zeek resolved from
     *                 the given path and is going to load. Empty string
     *                 if Zeek was not able to resolve a path.
     *
     * @return tuple of an integer and an optional string, where: the integer
     * must be 1 if the plugin takes over loading the file (see below); 0 if
     * the plugin wanted to take over the file but had trouble loading it
     * (processing will abort in this case, and the plugin should have printed
     * an error message); and -1 if the plugin wants Zeek to proceed processing
     * the file normally. If the plugins takes over by returning 1, there are
     * two cases: if the second tuple element remains unset, the plugin handled
     * the loading completely internally; Zeek will not do anything further with
     * it. Alternatively, the plugin may optionally return the actual content
     * to use for the file as a string through the tuple's second element. If
     * so, Zeek will ignore the file on disk and use that provided content
     * instead (including when there's actually no physical file in place on
     * disk at all, and loading would have hence failed otherwise).
     */
    virtual std::pair<int, std::optional<std::string>> HookLoadFileExtended(const LoadType type,
                                                                            const std::string& file,
                                                                            const std::string& resolved);

    /**
     * Hook into executing a script-level function/event/hook. Whenever
     * the script interpreter is about to execution a function, it first
     * gives all plugins with this hook enabled a chance to handle the
     * call (in the order of their priorities). A plugin can either just
     * inspect the call, or replace it (i.e., prevent the interpreter
     * from executing it). In the latter case it must provide a matching
     * return value.
     *
     * The default implementation never handles the call in any way.
     *
     * @param func The function being called.
     *
     * @param args The function arguments. The method can modify the list
     * in place as long as it ensures matching types and correct reference
     * counting.
     *
     * @return If the plugin handled the call, a pair with the first member
     * set to true, and a Val representing the result value to pass back to the
     * interpreter. If the plugin did not handle the call, it must return a
     * pair with the first member set to 'false' and null result value.
     */
    virtual std::pair<bool, ValPtr> HookFunctionCall(const Func* func, zeek::detail::Frame* parent, Args* args);

    /**
     * Hook into raising events. Whenever the script interpreter is about
     * to queue an event for later execution, it first gives all plugins
     * with this hook enabled a chance to handle the queuing otherwise
     * (in the order of their priorities). A plugin can either just
     * inspect the event, or take it over (i.e., prevent the interpreter
     * from queuing it itself).
     *
     * The default implementation never handles the queuing in any way.
     *
     * @param event The event to be queued. The method can modify it in
     * place as long as it ensures matching types and correct reference
     * counting.
     *
     * @return True if the plugin took charge of the event; in that case
     * it must have assumed ownership of the event and the interpreter will
     * not do anything further with it. False otherwise.
     */
    virtual bool HookQueueEvent(Event* event);

    /**
     * Hook into event queue draining. This method will be called
     * whenever the event manager is draining its queue.
     */
    virtual void HookDrainEvents();

    /**
     * Hook for updates to network time. This method will be called
     * whenever network time is advanced.
     *
     * @param network_time The new network time.
     */
    virtual void HookUpdateNetworkTime(double network_time);

    /**
     * Hook that executes when a connection's initial analyzer tree
     * has been fully set up. The hook can manipulate the tree at this time,
     * for example by adding further analyzers.
     *
     * @param conn The connection.
     */
    virtual void HookSetupAnalyzerTree(Connection* conn);

    /**
     * Hook for destruction of objects registered with
     * RequestObjDtor(). When Zeek's reference counting triggers the
     * objects destructor to run, this method will be run. It may also
     * run for other objects that this plugin has not registered for.
     *
     * @param obj A pointer to the object being destroyed. Note that the
     * object is already considered invalid and the pointer must not be
     * dereferenced.
     */
    virtual void HookObjDtor(void* obj);

    /**
     * Hook into log initialization. This method will be called when a
     * logging writer is created. A writer represents a single logging
     * filter. The method is called in the main thread, on the node that
     * causes a log line to be written. It will _not_ be called on the logger
     * node. The function will be called each for every instantiated writer.
     *
     * @param writer The name of the writer being instantiated.
     *
     * @param instantiating_filter Name of the filter causing the
     *        writer instantiation.
     *
     * @param local True if the filter is logging locally (writer
     *              thread will be located in same process).
     *
     * @param remote True if filter is logging remotely (writer thread
     *               will be located in different thread, typically
     *               in manager or logger node).
     *
     * @param info WriterBackend::WriterInfo with information about the writer.
     *
     * @param num_fields number of fields in the record being written.
     *
     * @param fields threading::Field description of the fields being logged.
     */
    virtual void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local,
                             bool remote, const logging::WriterBackend::WriterInfo& info, int num_fields,
                             const threading::Field* const* fields);

    /**
     * Hook into log writing. This method will be called for each log line
     * being written by each writer. Each writer represents a single logging
     * filter. The method is called in the main thread, on the node that
     * causes a log line to be written. It will _not_ be called on the logger
     * node.
     * This function allows plugins to modify or skip logging of information.
     * Note - once a log line is skipped (by returning false), it will not
     * passed on to hooks that have not yet been called.
     *
     * @param writer The name of the writer.
     *
     * @param filter Name of the filter being written to.
     *
     * @param info WriterBackend::WriterInfo with information about the writer.
     *
     * @param num_fields number of fields in the record being written.
     *
     * @param fields threading::Field description of the fields being logged.
     *
     * @param vals threading::Values containing the values being written. Values
     *             can be modified in the Hook.
     *
     * @return true if log line should be written, false if log line should be
     *         skipped and not passed on to the writer.
     */
    virtual bool HookLogWrite(const std::string& writer, const std::string& filter,
                              const logging::WriterBackend::WriterInfo& info, int num_fields,
                              const threading::Field* const* fields, threading::Value** vals);

    /**
     * Hook into reporting. This method will be called for each reporter call
     * made; this includes weirds. The method cannot manipulate the data at
     * the current time; however it is possible to prevent script-side events
     * from being called by returning false.
     *
     * @param prefix The prefix passed by the reporter framework
     *
     * @param event The event to be called
     *
     * @param conn The associated connection
     *
     * @param addl Additional Zeek values; typically will be passed to the event
     *             by the reporter framework.
     *
     * @param location True if event expects location information
     *
     * @param location1 First location
     *
     * @param location2 Second location
     *
     * @param time True if event expects time information
     *
     * @param message Message supplied by the reporter framework
     *
     * @return true if event should be called by the reporter framework, false
     *         if the event call should be skipped
     */
    virtual bool HookReporter(const std::string& prefix, const EventHandlerPtr event, const Connection* conn,
                              const ValPList* addl, bool location, const zeek::detail::Location* location1,
                              const zeek::detail::Location* location2, bool time, const std::string& message);

    /**
     * Hook for packets that are considered unprocessed by an Analyzer. This
     * typically means that a packet has not had a log entry written for it by
     * the time analysis finishes.
     *
     * @param packet The data for an unprocessed packet
     */
    virtual void HookUnprocessedPacket(const Packet* packet);

    /**
     * Hook for intercepting remote event publish operations.
     *
     * This hook is invoked when Cluster::publish(), Cluster::publish_hrw() or
     * Cluster::publish_rr() is used in the scripting layer to publish a remote
     * event to a topic. It is also invoked when calling PublishEvent() on the
     * active cluster backend directly from C++ plugins. This hook can be used
     * for metrics collection, modifying or redirecting events to a different
     * topic. It's event possible to translate an event to another one. A plugin
     * should return false if it took responsibility of publishing the event, or
     * the verdict is to skip the publish operation.
     *
     * @param backend The backend publishing this event
     * @param topic The topic to which to publish this event
     * @param event The event itself
     *
     * @return true if event should be published, false if the publish
     *         operation should be skipped.
     */
    virtual bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                                  zeek::cluster::detail::Event& event);

    // Meta hooks.
    virtual void MetaHookPre(HookType hook, const HookArgumentList& args);
    virtual void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result);

private:
    /**
     * A function called when the plugin is instantiated to query basic
     * configuration parameters.
     *
     * The plugin must override this method and return a suitably
     * initialized configuration object.
     *
     * @return A configuration describing the plugin.
     */
    virtual Configuration Configure() = 0;

    /**
     * Initializes the plugin's internal configuration. Called by the
     * manager before anything else.
     */
    void DoConfigure();

    /**
     * Sets the base directory and shared library path from which the
     * plugin was loaded.
     *
     * This is called by the manager.
     *
     * @param dir The plugin directory. The functions makes an internal
     * copy of string.
     *
     * @param sopath The full path the shared library loaded. The
     * functions makes an internal copy of string.
     */
    void SetPluginLocation(const std::string& dir, const std::string& sopath);

    /**
     * Marks the plugin as dynamically loaded.
     *
     * This is called by the manager.
     *
     * @param is_dynamic True if it's a dynamically loaded module.
     */
    void SetDynamic(bool is_dynamic);

    Configuration config;

    std::string base_dir; // The plugin's base directory.
    std::string sopath;   // For dynamic plugins, the full path to the shared library.
    bool dynamic;         // True if a dynamic plugin.

    component_list components; // Components the plugin provides.
    bif_item_list bif_items;   // BiF items the plugin provides.
};

} // namespace plugin
} // namespace zeek
