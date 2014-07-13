// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DataSeries.h"

namespace plugin {
namespace Bro_DataSeriesWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::logging::Component("DataSeries", ::logging::writer::DataSeries::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::DataSeriesWriter";
		config.description = "DataSeries log writer";
		return config;
		}
} plugin;

}
}
