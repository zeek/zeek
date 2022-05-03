// See the file  in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/mqtt/MQTT.h"

#include "zeek/Reporter.h"

#include "analyzer/protocol/mqtt/mqtt_pac.h"

namespace zeek::analyzer::mqtt
	{

MQTT_Analyzer::MQTT_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("MQTT", c)
	{
	interp = new binpac::MQTT::MQTT_Conn(this);
	}

MQTT_Analyzer::~MQTT_Analyzer()
	{
	delete interp;
	}

void MQTT_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void MQTT_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void MQTT_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void MQTT_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

	} // namespace zeek::analyzer::mqtt
