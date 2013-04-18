
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
			SetName(#_name);			\
			SetVersion(_BRO_PLUGIN_VERSION_DEFAULT);	\
			SetAPIVersion(BRO_PLUGIN_API_VERSION);

#define BRO_PLUGIN_END				\
			}			\
		};				\
						\
	static Plugin __plugin;			\
	} }

#define BRO_PLUGIN_DESCRIPTION(x) SetDescription(x)
#define BRO_PLUGIN_VERSION(x) SetVersion(x)

#define BRO_PLUGIN_BIF_FILE(file)			\
		std::list<std::pair<const char*, int> >  __bif_##file##_init();	\
		AddBifInitFunction(&__bif_##file##_init);

#define BRO_PLUGIN_ANALYZER(tag, cls) \
	AddComponent(new ::analyzer::Component(tag, ::analyzer::cls::InstantiateAnalyzer));

#define BRO_PLUGIN_ANALYZER_BARE(tag) \
	AddComponent(new ::analyzer::Component(tag, 0));

#define BRO_PLUGIN_SUPPORT_ANALYZER(tag) \
	AddComponent(new ::analyzer::Component(tag, 0));

#endif
