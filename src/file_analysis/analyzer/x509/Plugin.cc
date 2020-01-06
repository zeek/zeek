// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "X509.h"
#include "OCSP.h"

namespace plugin {
namespace Zeek_X509 {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("X509", ::file_analysis::X509::Instantiate));
		AddComponent(new ::file_analysis::Component("OCSP_REQUEST", ::file_analysis::OCSP::InstantiateRequest));
		AddComponent(new ::file_analysis::Component("OCSP_REPLY", ::file_analysis::OCSP::InstantiateReply));

		plugin::Configuration config;
		config.name = "Zeek::X509";
		config.description = "X509 and OCSP analyzer";
		return config;
		}

	void Done() override
		{
		plugin::Plugin::Done();
		::file_analysis::X509::FreeRootStore();
		}
} plugin;

}
}
