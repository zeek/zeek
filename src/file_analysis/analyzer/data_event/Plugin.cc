#include "plugin/Plugin.h"

#include "DataEvent.h"

BRO_PLUGIN_BEGIN(Bro, FileDataEvent)
	BRO_PLUGIN_DESCRIPTION("Delivers file content via events");
	BRO_PLUGIN_FILE_ANALYZER("DATA_EVENT", DataEvent);
BRO_PLUGIN_END
