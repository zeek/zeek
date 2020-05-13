// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "MQTT.h"
#include "Reporter.h"
#include "Scope.h"
#include "mqtt_pac.h"

using namespace analyzer::MQTT;

MQTT_Analyzer::MQTT_Analyzer(Connection* c)
	: tcp::TCP_ApplicationAnalyzer("MQTT", c)
	{
	interp = new binpac::MQTT::MQTT_Conn(this);
	}

MQTT_Analyzer::~MQTT_Analyzer()
	{
	delete interp;
	}

void MQTT_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void MQTT_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void MQTT_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void MQTT_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
