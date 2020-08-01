// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <iostream>
#include <vector>
#include <fstream>
#include <memory>
#include <sys/types.h>

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {

// Description for input field mapping.
struct FieldMapping {
	std::string name;
	zeek::TypeTag type;
	zeek::TypeTag subtype; // internal type for sets and vectors
	int position;
	int secondary_position; // for ports: pos of the second field
	bool present;

	FieldMapping(const std::string& arg_name, const zeek::TypeTag& arg_type, int arg_position);
	FieldMapping(const std::string& arg_name, const zeek::TypeTag& arg_type, const zeek::TypeTag& arg_subtype, int arg_position);

	FieldMapping(const FieldMapping& arg);
	FieldMapping() { position = -1; secondary_position = -1; }

	FieldMapping subType();
};

/**
 * Reader for structured ASCII files.
 */
class Ascii : public zeek::input::ReaderBackend {
public:
	explicit Ascii(zeek::input::ReaderFrontend* frontend);
	~Ascii() override;

	// prohibit copying and moving
	Ascii(const Ascii&) = delete;
	Ascii(Ascii&&) = delete;
	Ascii& operator=(const Ascii&) = delete;
	Ascii& operator=(Ascii&&) = delete;

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend) { return new Ascii(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	bool ReadHeader(bool useCached);
	bool GetLine(std::string& str);
	bool OpenFile();

	std::ifstream file;
	time_t mtime;
	ino_t ino;

	// The name using which we actually load the file -- compared
	// to the input source name, this one may have a path_prefix
	// attached to it.
	std::string fname;

	// map columns in the file to columns to send back to the manager
	std::vector<FieldMapping> columnMap;

	// keep a copy of the headerline to determine field locations when stream descriptions change
	std::string headerline;

	// options set from the script-level.
	std::string separator;
	std::string set_separator;
	std::string empty_field;
	std::string unset_field;
	bool fail_on_invalid_lines;
	bool fail_on_file_problem;
	std::string path_prefix;

	std::unique_ptr<zeek::threading::Formatter> formatter;
};

} // namespace zeek::input::reader::detail

namespace input::reader {
	using FieldMapping [[deprecated("Remove in v4.1. Use zeek::input::reader::detail::FieldMapping.")]] = zeek::input::reader::detail::FieldMapping;
	using Ascii [[deprecated("Remove in v4.1. Use zeek::input::reader::detail::Ascii.")]] = zeek::input::reader::detail::Ascii;
} // namespace input::reader
