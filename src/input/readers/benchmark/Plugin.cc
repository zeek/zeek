// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Benchmark.h"

namespace plugin {
namespace Zeek_BenchmarkReader {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::input::Component("Benchmark", ::input::reader::Benchmark::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::BenchmarkReader";
		config.description = "Benchmark input reader";
		return config;
		}
} plugin;

}
}
