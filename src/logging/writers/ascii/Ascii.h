// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for delimiter-separated ASCII logs.

#pragma once

#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"
#include "threading/formatters/JSON.h"
#include "Desc.h"
#include "zlib.h"

namespace zeek::plugin::Zeek_AsciiWriter { class Plugin; }

namespace zeek::logging::writer::detail {

class Ascii : public zeek::logging::WriterBackend {
public:
	explicit Ascii(zeek::logging::WriterFrontend* frontend);
	~Ascii() override;

	static std::string LogExt();

	static zeek::logging::WriterBackend* Instantiate(zeek::logging::WriterFrontend* frontend)
		{ return new Ascii(frontend); }

protected:
	bool DoInit(const WriterInfo& info, int num_fields,
	            const zeek::threading::Field* const* fields) override;
	bool DoWrite(int num_fields, const zeek::threading::Field* const* fields,
			     zeek::threading::Value** vals) override;
	bool DoSetBuf(bool enabled) override;
	bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating) override;
	bool DoFlush(double network_time) override;
	bool DoFinish(double network_time) override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	friend class plugin::Zeek_AsciiWriter::Plugin;

	static void RotateLeftoverLogs();

	bool IsSpecial(const std::string &path) 	{ return path.find("/dev/") == 0; }
	bool WriteHeader(const std::string& path);
	bool WriteHeaderField(const std::string& key, const std::string& value);
	void CloseFile(double t);
	std::string Timestamp(double t); // Uses current time if t is zero.
	void InitConfigOptions();
	bool InitFilterOptions();
	bool InitFormatter();
	bool InternalWrite(int fd, const char* data, int len);
	bool InternalClose(int fd);

	int fd;
	gzFile gzfile;
	std::string fname;
	zeek::ODesc desc;
	bool ascii_done;

	// Options set from the script-level.
	bool output_to_stdout;
	bool include_meta;
	bool tsv;

	std::string separator;
	std::string set_separator;
	std::string empty_field;
	std::string unset_field;
	std::string meta_prefix;

	int gzip_level; // level > 0 enables gzip compression
	std::string gzip_file_extension;
	bool use_json;
	bool enable_utf_8;
	std::string json_timestamps;

	zeek::threading::Formatter* formatter;
	bool init_options;
};

} // namespace zeek::logging::writer::detail
