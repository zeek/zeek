
#ifndef PLUGIN_MACROS_H
#define PLUGIN_MACROS_H

#include "analyzer/Component.h"

#define BRO_PLUGIN_VERSION_BUILTIN -1
#define BRO_PLUGIN_API_VERSION      1

#define _BRO_PLUGIN_VERSION_DEFAULT -1

#define BRO_PLUGIN_BEGIN(_name)					\
	namespace plugin { namespace _name {			\
		class Plugin : public plugin::Plugin {		\
		protected:					\
			void Init()				\
			{					\
			plugin::Description _desc;		\
			_desc.name = #_name;			\
			_desc.version = _BRO_PLUGIN_VERSION_DEFAULT;	\
			_desc.api_version = BRO_PLUGIN_API_VERSION;

#define BRO_PLUGIN_END				\
			SetDescription(_desc);	\
			}			\
		};				\
						\
	static Plugin __plugin;			\
	} }

#define BRO_PLUGIN_DESCRIPTION _desc.description
#define BRO_PLUGIN_URL         _desc.url
#define BRO_PLUGIN_VERSION     _desc.version

#define BRO_PLUGIN_BIF_FILE(file)			\
		std::list<std::pair<std::string, int> >  __bif_##file##_init();	\
		AddBifInitFunction(&__bif_##file##_init);

#define BRO_PLUGIN_ANALYZER(tag, factory) \
	AddComponent(new ::analyzer::Component(tag, factory));

#define BRO_PLUGIN_ANALYZER_EXT(tag, factory, enabled, partial) \
	AddComponent(new ::analyzer::Component(tag, factory, 0, enabled, partial));

#endif
