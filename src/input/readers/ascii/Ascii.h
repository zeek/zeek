// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

#include "zeek/Obj.h"
#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/formatters/Ascii.h"

namespace zeek::input::reader::detail
	{

// Description for input field mapping.
struct FieldMapping
	{
	std::string name;
	TypeTag type;
	TypeTag subtype; // internal type for sets and vectors
	int position = -1;
	int secondary_position = -1; // for ports: pos of the second field
	bool present = false;

	FieldMapping(const std::string& arg_name, const TypeTag& arg_type, int arg_position);
	FieldMapping(const std::string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype,
	             int arg_position);

	FieldMapping(const FieldMapping& arg);
	FieldMapping() = default;

	FieldMapping& operator=(const FieldMapping& arg);

	FieldMapping subType();
	};

/**
 * Reader for structured ASCII files.
 */
class Ascii : public ReaderBackend
	{
public:
	explicit Ascii(ReaderFrontend* frontend);
	~Ascii() override = default;

	// prohibit copying and moving
	Ascii(const Ascii&) = delete;
	Ascii(Ascii&&) = delete;
	Ascii& operator=(const Ascii&) = delete;
	Ascii& operator=(Ascii&&) = delete;

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Ascii(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields,
	            const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

	const zeek::detail::Location* GetLocationInfo() const override { return read_location.get(); }

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

	// zeek::detail::Location doesn't have a destructor because it's constexpr, so we have to
	// define a custom deleter for the unique_ptr here to make sure the filename gets deleted
	// correctly when the unique_ptr gets reset.
	struct LocationDeleter
		{
		void operator()(zeek::detail::Location* loc) const
			{
			delete[] loc->filename;
			delete loc;
			}
		};

	using LocationPtr = std::unique_ptr<zeek::detail::Location, LocationDeleter>;
	LocationPtr read_location;
	};

	} // namespace zeek::input::reader::detail
