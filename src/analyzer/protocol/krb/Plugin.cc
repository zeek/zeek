//See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "KRB.h"
#include "KRB_TCP.h"

namespace plugin {
	namespace Bro_KRB {
		class Plugin : public plugin::Plugin {
		public:
			plugin::Configuration Configure()
				{
				AddComponent(new ::analyzer::Component("KRB", ::analyzer::krb::KRB_Analyzer::Instantiate));
				AddComponent(new ::analyzer::Component("KRB_TCP", ::analyzer::krb_tcp::KRB_Analyzer::Instantiate));
				plugin::Configuration config;
				config.name = "Bro::KRB";
				config.description = "Kerberos analyzer";
				return config;
				}
		} plugin;
	}
}
