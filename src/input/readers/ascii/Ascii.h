// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_ASCII_H
#define INPUT_READERS_ASCII_H

#include <iostream>
#include <vector>
#include <fstream>
#include <memory>

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace input { namespace reader {

// Description for input field mapping.
struct FieldMapping {
	string name;
	TypeTag type;
	TypeTag subtype; // internal type for sets and vectors
	int position;
	int secondary_position; // for ports: pos of the second field
	bool present;

	FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position);
	FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position);
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
	~Ascii();

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
	bool GetLine(string& str);

	ifstream file;
	time_t mtime;

	// map columns in the file to columns to send back to the manager
	vector<FieldMapping> columnMap;

	// keep a copy of the headerline to determine field locations when stream descriptions change
	string headerline;

	// options set from the script-level.
	string separator;
	string set_separator;
	string empty_field;
	string unset_field;

	std::unique_ptr<threading::formatter::Formatter> formatter;
};


}
}

#endif /* INPUT_READERS_ASCII_H */
