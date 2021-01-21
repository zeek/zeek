// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <memory>

#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {

// Description for input field mapping.
struct FieldMapping {
	std::string name;
	TypeTag type;
	TypeTag subtype; // internal type for sets and vectors
	int position;
	int secondary_position; // for ports: pos of the second field
	bool present;

	FieldMapping(const std::string& arg_name, const TypeTag& arg_type, int arg_position);
	FieldMapping(const std::string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position);

	FieldMapping(const FieldMapping& arg);
	FieldMapping() { position = -1; secondary_position = -1; }

	FieldMapping subType();
};

/**
 * Reader for structured ASCII files.
 */
class Ascii : public ReaderBackend {
public:
	explicit Ascii(ReaderFrontend* frontend);
	~Ascii() override;

	// prohibit copying and moving
	Ascii(const Ascii&) = delete;
	Ascii(Ascii&&) = delete;
	Ascii& operator=(const Ascii&) = delete;
	Ascii& operator=(Ascii&&) = delete;

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Ascii(frontend); }

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

	std::unique_ptr<threading::Formatter> formatter;
};

} // namespace zeek::input::reader::detail
