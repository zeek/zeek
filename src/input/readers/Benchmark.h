// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_BENCHMARK_H
#define INPUT_READERS_BENCHMARK_H

#include "../ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace input { namespace reader {

/**
 * A benchmark reader to measure performance of the input framework.
 */
class Benchmark : public ReaderBackend {
public:
	Benchmark(ReaderFrontend* frontend);
	~Benchmark();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Benchmark(frontend); }

protected:
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	double CurrTime();
	string RandomString(const int len);
	threading::Value* EntryToVal(TypeTag Type, TypeTag subtype);

	int num_lines;
	double multiplication_factor;
	int spread;
	double autospread;
	int autospread_time;
	int add;
	int stopspreadat;
	double heartbeatstarttime;
	double timedspread;
	double heartbeat_interval;

	threading::formatter::Ascii* ascii;
};


}
}

#endif /* INPUT_READERS_BENCHMARK_H */
