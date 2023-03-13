#include "Plugin.h"

extern "C"
	{
#include <Python.h>
	}

namespace zeek::plugin::Zeek_PyLib
	{
Plugin plugin;
	}

using namespace zeek::plugin::Zeek_PyLib;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::PyLib";
	config.description = "Plugin embedding Python, whoosh.";
	config.version.major = 0;
	config.version.minor = 0;
	config.version.patch = 1;
	return config;
	}

void Plugin::InitPostScript()
	{
	Py_Initialize();
	}

void Plugin::Done()
	{
	Py_FinalizeEx();
	}
