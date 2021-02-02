// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <memory>
#include <unordered_map>

#include "zeek/ID.h"
#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {

/**
 * Reader for Configuration files.
 */
class Config : public ReaderBackend {
public:
	explicit Config(ReaderFrontend* frontend);
	~Config() override;

	// prohibit copying and moving
	Config(const Config&) = delete;
	Config(Config&&) = delete;
	Config& operator=(const Config&) = delete;
	Config& operator=(Config&&) = delete;

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Config(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	bool GetLine(std::string& str);
	bool OpenFile();

	std::ifstream file;
	time_t mtime;
	ino_t ino;

	bool fail_on_file_problem;

	std::string set_separator;
	std::string empty_field;

	std::unique_ptr<threading::Formatter> formatter;
	std::unordered_map<std::string, std::tuple<TypeTag, TypeTag, zeek::detail::IDPtr>> option_types;
	std::unordered_map<std::string, std::string> option_values;
};

} // namespace zeek::input::reader::detail
