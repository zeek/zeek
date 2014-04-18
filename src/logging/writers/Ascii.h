// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for delimiter-separated ASCII logs.

#ifndef LOGGING_WRITER_ASCII_H
#define LOGGING_WRITER_ASCII_H

#include "../WriterBackend.h"
#include "threading/formatters/Ascii.h"
#include "threading/formatters/JSON.h"

namespace logging { namespace writer {

class Ascii : public WriterBackend {
public:
	Ascii(WriterFrontend* frontend);
	~Ascii();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new Ascii(frontend); }
	static string LogExt();

protected:
	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const* fields);
	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating);
	virtual bool DoFlush(double network_time);
	virtual bool DoFinish(double network_time);
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	bool IsSpecial(string path) 	{ return path.find("/dev/") == 0; }
	bool WriteHeader(const string& path);
	bool WriteHeaderField(const string& key, const string& value);
	void CloseFile(double t);
	string Timestamp(double t); // Uses current time if t is zero.
	void InitConfigOptions();
	bool InitFilterOptions();
	bool InitFormatter();

	int fd;
	string fname;
	ODesc desc;
	bool ascii_done;

	// Options set from the script-level.
	bool output_to_stdout;
	bool include_meta;
	bool tsv;

	string separator;
	string set_separator;
	string empty_field;
	string unset_field;
	string meta_prefix;

	bool use_json;
	string json_timestamps;

	threading::formatter::Formatter* formatter;
	bool init_options;
};

}
}


#endif
