
#include "plugin/Plugin.h"

#include "KRB.h"

BRO_PLUGIN_BEGIN(Bro, KRB)
	BRO_PLUGIN_DESCRIPTION("Kerberos analyzer");
	BRO_PLUGIN_ANALYZER("KRB", krb::KRB_Analyzer);
	BRO_PLUGIN_BIF_FILE(types);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
