// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Benchmark.h"

namespace plugin {
namespace Bro_BenchmarkReader {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::input::Component("Benchmark", ::input::reader::Benchmark::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::BenchmarkReader";
		config.description = "Benchmark input reader";
		return config;
		}
} plugin;

}
}
