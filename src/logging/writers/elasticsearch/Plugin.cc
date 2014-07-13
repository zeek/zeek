// See the file  in the main distribution directory for copyright.

#include <curl/curl.h>

#include "plugin/Plugin.h"

#include "ElasticSearch.h"

namespace plugin {
namespace Bro_ElasticSearchWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::logging::Component("ElasticSearch", ::logging::writer::ElasticSearch::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::ElasticSearchWriter";
		config.description = "ElasticSearch log writer";
		return config;
		}

	virtual void InitPreScript()
		{
		curl_global_init(CURL_GLOBAL_ALL);
		}

	virtual void Done()
		{
		curl_global_cleanup();
		}

} plugin;

}
}
