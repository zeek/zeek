// See the file "COPYING" in the main distribution directory for copyright.

/**
 * A set of macros wrapping internal logic for defining plugins and
 * components.
 */

#ifndef PLUGIN_MACROS_H
#define PLUGIN_MACROS_H

#include "analyzer/Component.h"
#include "file_analysis/Component.h"

/**
 * The current plugin API version. Plugins that won't match this version will
 * be rejected.
 */
#define BRO_PLUGIN_API_VERSION      1

/**
 * Starts the definition of a new plugin.
 *
 * @param _ns: A namespace for the plugin. All plugins compiled in statically
 * must use the reserved "Bro" namespace. External plugins should define
 * their own namespace to avoid collisions.
 *
 * @param _name: The plugin's name. The combiniation of namespace and name
 * must be unique across all loaded plugins.
 */
#define BRO_PLUGIN_BEGIN(_ns, _name)				\
	namespace plugin { namespace _ns ## _ ## _name {\
		class Plugin : public plugin::Plugin {		\
		protected:					\
			void InitPreScript()				\
			{					\
			SetName(#_ns "::" #_name);		\
			SetVersion(-1);\
			SetAPIVersion(BRO_PLUGIN_API_VERSION);\
			SetDynamicPlugin(false);
// TODO: The SetDynamicPlugin() call is currently hardcoded to false. Change
// once we have dynamic plugins as well.


/**
 * Ends the definition of a plugin.
 */
#define BRO_PLUGIN_END				\
			}			\
		};				\
						\
	Plugin __plugin;			\
	} }

/**
 * Provides a textual description for a plugin.
 *
 * @param d A string with the description.
 */
#define BRO_PLUGIN_DESCRIPTION(d) SetDescription(d)

/**
 * Defines a version of the plugin. The version is mostly informational for
 * the user; if a plugin's functionality changes, the version should be
 * increased.
 *
 * @param v An integer version.
 */
#define BRO_PLUGIN_VERSION(v) SetVersion(v)

/**
 * Adds script-level items defined in a \c *.bif file to what the plugin
 * provides.
 *
 * @param file A string with the name of \c *.bif file. When loaded, the
 * plugin will make all items defined in the file available to Bro's script
 * interpreter.
 */
#define BRO_PLUGIN_BIF_FILE(file)			\
		extern std::list<std::pair<const char*, int> >  __bif_##file##_init();	\
		AddBifInitFunction(&__bif_##file##_init);

/**
 * Defines a component implementing a protocol analyzer.
 *
 * @param tag A string with the analyzer's tag. This must be unique across
 * all loaded analyzers and will translate into a corresponding \c ANALYZER_*
 * constant at the script-layer.
 *
 * @param cls The class that implements the analyzer. It must be derived
 * (directly or indirectly) from analyzer::Analyzer.
 */
#define BRO_PLUGIN_ANALYZER(tag, cls) \
	AddComponent(new ::analyzer::Component(tag, ::analyzer::cls::InstantiateAnalyzer));

/**
 * Defines a component implementing a file analyzer.
 *
 * @param tag A string with the analyzer's tag. This must be unique across
 * all loaded analyzers and will translate into a corresponding \c ANALYZER_*
 * constant at the script-layer.
 *
 * @param cls The class that implements the analyzer. It must be derived
 * (directly or indirectly) from file_analysis::Analyzer.
 */
#define BRO_PLUGIN_FILE_ANALYZER(tag, cls) \
	AddComponent(new ::file_analysis::Component(tag, ::file_analysis::cls::Instantiate));

/**
 * Defines a component implementing a protocol analyzer class that will
 * not be instantiated dynamically. This is for two use-cases: (1) abstract
 * analyzer base classes that aren't instantiated directly; and (2) analyzers
 * that are only instantiated explicitly by other Bro components, but not
 * dynamically by the manager based on their tag (e.g., the ZIP analyzer is
 * attached by the HTTP analyzer when corresponding content is found).
 *
 * @param tag A string with the analyzer's tag. This must be unique across
 * all loaded analyzers and will translate into a corresponding \c ANALYZER_*
 * constant at the script-layer.
 */
#define BRO_PLUGIN_ANALYZER_BARE(tag) \
	AddComponent(new ::analyzer::Component(tag, 0));

/**
 * Defines a component implementating a support analyzer.
 *
 * @param tag A string with the analyzer's tag. This must be unique across
 * all loaded analyzers and will translate into a corresponding \c ANALYZER_*
 * constant at the script-layer.
 */
#define BRO_PLUGIN_SUPPORT_ANALYZER(tag) \
	AddComponent(new ::analyzer::Component(tag, 0));

#endif
