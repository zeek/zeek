// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {

/**
 * A benchmark reader to measure performance of the input framework.
 */
class Benchmark : public zeek::input::ReaderBackend {
public:
	explicit Benchmark(zeek::input::ReaderFrontend* frontend);
	~Benchmark() override;

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend) { return new Benchmark(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	double CurrTime();
	std::string RandomString(const int len);
	threading::Value* EntryToVal(zeek::TypeTag Type, zeek::TypeTag subtype);

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

	zeek::threading::formatter::Ascii* ascii;
};

} // namespace zeek::input::reader

namespace input::reader {
	using Benchmark [[deprecated("Remove in v4.1. Use zeek::input::reader::detail::Benchmark.")]] = zeek::input::reader::detail::Benchmark;
}
