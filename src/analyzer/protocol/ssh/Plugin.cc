// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "SSH.h"

namespace plugin {
	namespace Bro_SSH {

		class Plugin : public plugin::Plugin {
		public:
			plugin::Configuration Configure()
				{
				AddComponent(new ::analyzer::Component("SSH", ::analyzer::SSH::SSH_Analyzer::Instantiate));

				plugin::Configuration config;
				config.name = "Bro::SSH";
				config.description = "Secure Shell analyzer";
				return config;
				}
			} plugin;

		}
	}

