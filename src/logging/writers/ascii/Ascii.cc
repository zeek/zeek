// See the file "COPYING" in the main distribution directory for copyright.

#include <ctime>
#include <cstdio>
#include <string>
#include <vector>
#include <memory>
#include <optional>

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "Func.h"
#include "supervisor/Supervisor.h"
#include "logging/Manager.h"
#include "threading/SerialTypes.h"

#include "Ascii.h"
#include "ascii.bif.h"

using namespace std;
using namespace logging::writer;
using namespace threading;
using threading::Value;
using threading::Field;

static constexpr auto shadow_file_prefix = ".shadow.";

/**
 * Information about an leftover log file: that is, one that a previous
 * process was in the middle of writing, but never completed a rotation
 * for whatever reason (prematurely crashed/killed).
 */
struct LeftoverLog {
	/*
	 * Name of leftover log, relative to working dir.
	 */
	std::string filename;

	/*
	 * File extension of the leftover log (e.g. ".log").
	 */
	std::string extension;

	/*
	 * Name of shadow file associated with the log.
	 * The shadow file's existence is what indicates the presence of
	 * an "leftover log" and may contain the name of a postprocessing
	 * function that's supposed to be called after rotating (only
	 * named if that function differs from the default).  Upon
	 * completing a rotation, the shadow file can be deleted.
	 */
	std::string shadow_filename;

	/**
	 * Name of a function to call to postprocess the log file after
	 * rotating.
	 */
	std::string post_proc_func;

	/**
	 * The time at which the shadow file was created.  This is used
	 * as the log file's "opening time" for rotation purposes.
	 */
	time_t open_time;

	/**
	 * Time of the log file's last modification.  This is used
	 * as the log file's "closing time" for rotation purposes.
	 */
	time_t close_time;

	/**
	 * Set the an error message explaining any error that happened while
	 * trying to parse the shadow file and construct an object.
	 */
	std::string error;

	/**
	 * Return the name of the log without file extension (this is
	 * what's called "path" in other logging framework parlance).
	 * E.g. the name of "conn.log" is just "conn".
	 */
	std::string Name() const
		{ return filename.substr(0, filename.size() - extension.size()); }

	/**
	 * Deletes the shadow file and returns whether it succeeded.
	 */
	bool DeleteShadow() const
		{ return unlink(shadow_filename.data()) == 0; }
};

static std::optional<LeftoverLog> parse_shadow_log(const std::string& fname)
	{
	char errbuf[512];
	auto sfname = shadow_file_prefix + fname;

	LeftoverLog rval;
	rval.filename = fname;
	rval.shadow_filename = std::move(sfname);

	auto sf_stream = fopen(rval.shadow_filename.data(), "r");

	if ( ! sf_stream )
		{
		bro_strerror_r(errno, errbuf, sizeof(errbuf));
		rval.error = "Failed to open " + rval.shadow_filename + ": " + errbuf;
		return rval;
		}

	fseek(sf_stream, 0, SEEK_END);
	auto sf_len = ftell(sf_stream);
	fseek(sf_stream, 0, SEEK_SET);

	auto sf_content = std::make_unique<char[]>(sf_len);
	auto bytes_read = fread(sf_content.get(), 1, sf_len, sf_stream);

	if ( bytes_read != static_cast<size_t>(sf_len) )
		{
		rval.error = "Failed to read contents of " + rval.shadow_filename;
		return rval;
		}

	fclose(sf_stream);
	std::string_view sf_view(sf_content.get(), sf_len);
	auto sf_lines = tokenize_string(sf_view, '\n');

	if ( sf_lines.size() < 2 )
		{
		snprintf(errbuf, sizeof(errbuf),
		         "Found leftover log, '%s', but the associated shadow file, "
		         "'%s', required to process it is invalid",
		         rval.filename.data(), rval.shadow_filename.data());
		rval.error = errbuf;
		return rval;
		}

	rval.extension = sf_lines[0];
	rval.post_proc_func = sf_lines[1];

	struct stat st;

	// Use shadow file's modification time as creation time.
	if ( stat(rval.shadow_filename.data(), &st) != 0 )
		{
		bro_strerror_r(errno, errbuf, sizeof(errbuf));
		rval.error = "Failed to stat " + rval.shadow_filename + ": " + errbuf;
		return rval;
		}

	rval.open_time = st.st_ctime;

	// Use log file's modification time for closing time.
	if ( stat(rval.filename.data(), &st) != 0 )
		{
		bro_strerror_r(errno, errbuf, sizeof(errbuf));
		rval.error = "Failed to stat " + rval.filename + ": " + errbuf;
		return rval;
		}

	rval.close_time = st.st_mtime;

	return rval;
	}

Ascii::Ascii(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	fd = 0;
	ascii_done = false;
	output_to_stdout = false;
	include_meta = false;
	tsv = false;
	use_json = false;
	enable_utf_8 = false;
	formatter = nullptr;
	gzip_level = 0;
	gzfile = nullptr;

	InitConfigOptions();
	init_options = InitFilterOptions();
	}

void Ascii::InitConfigOptions()
	{
	output_to_stdout = zeek::BifConst::LogAscii::output_to_stdout;
	include_meta = zeek::BifConst::LogAscii::include_meta;
	use_json = zeek::BifConst::LogAscii::use_json;
	enable_utf_8 = zeek::BifConst::LogAscii::enable_utf_8;
	gzip_level = zeek::BifConst::LogAscii::gzip_level;

	separator.assign(
			(const char*) zeek::BifConst::LogAscii::separator->Bytes(),
			zeek::BifConst::LogAscii::separator->Len()
			);

	set_separator.assign(
			(const char*) zeek::BifConst::LogAscii::set_separator->Bytes(),
			zeek::BifConst::LogAscii::set_separator->Len()
			);

	empty_field.assign(
			(const char*) zeek::BifConst::LogAscii::empty_field->Bytes(),
			zeek::BifConst::LogAscii::empty_field->Len()
			);

	unset_field.assign(
			(const char*) zeek::BifConst::LogAscii::unset_field->Bytes(),
			zeek::BifConst::LogAscii::unset_field->Len()
			);

	meta_prefix.assign(
			(const char*) zeek::BifConst::LogAscii::meta_prefix->Bytes(),
			zeek::BifConst::LogAscii::meta_prefix->Len()
			);

	ODesc tsfmt;
	zeek::BifConst::LogAscii::json_timestamps->Describe(&tsfmt);
	json_timestamps.assign(
			(const char*) tsfmt.Bytes(),
			tsfmt.Len()
			);

	gzip_file_extension.assign(
		(const char*) zeek::BifConst::LogAscii::gzip_file_extension->Bytes(),
		zeek::BifConst::LogAscii::gzip_file_extension->Len()
		);
	}

bool Ascii::InitFilterOptions()
	{
	const WriterInfo& info = Info();

	// Set per-filter configuration options.
	for ( WriterInfo::config_map::const_iterator i = info.config.begin();
	      i != info.config.end(); ++i )
		{
		if ( strcmp(i->first, "tsv") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				tsv = true;
			else if ( strcmp(i->second, "F") == 0 )
				tsv = false;
			else
				{
				Error("invalid value for 'tsv', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "gzip_level" ) == 0 )
			{
			gzip_level = atoi(i->second);

			if ( gzip_level < 0 || gzip_level > 9 )
				{
				Error("invalid value for 'gzip_level', must be a number between 0 and 9.");
				return false;
				}
			}
		else if ( strcmp(i->first, "use_json") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				use_json = true;
			else if ( strcmp(i->second, "F") == 0 )
				use_json = false;
			else
				{
				Error("invalid value for 'use_json', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "enable_utf_8") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				enable_utf_8 = true;
			else if ( strcmp(i->second, "F") == 0 )
				enable_utf_8 = false;
			else
				{
				Error("invalid value for 'enable_utf_8', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "output_to_stdout") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				output_to_stdout = true;
			else if ( strcmp(i->second, "F") == 0 )
				output_to_stdout = false;
			else
				{
				Error("invalid value for 'output_to_stdout', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "separator") == 0 )
			separator.assign(i->second);

		else if ( strcmp(i->first, "set_separator") == 0 )
			set_separator.assign(i->second);

		else if ( strcmp(i->first, "empty_field") == 0 )
			empty_field.assign(i->second);

		else if ( strcmp(i->first, "unset_field") == 0 )
			unset_field.assign(i->second);

		else if ( strcmp(i->first, "meta_prefix") == 0 )
			meta_prefix.assign(i->second);

		else if ( strcmp(i->first, "json_timestamps") == 0 )
			json_timestamps.assign(i->second);

		else if ( strcmp(i->first, "gzip_file_extension") == 0 )
			gzip_file_extension.assign(i->second);
		}

	if ( ! InitFormatter() )
		return false;

	return true;
	}

bool Ascii::InitFormatter()
	{
	delete formatter;
	formatter = nullptr;

	if ( use_json )
		{
		formatter::JSON::TimeFormat tf = formatter::JSON::TS_EPOCH;

		// Write out JSON formatted logs.
		if ( strcmp(json_timestamps.c_str(), "JSON::TS_EPOCH") == 0 )
			tf = formatter::JSON::TS_EPOCH;
		else if ( strcmp(json_timestamps.c_str(), "JSON::TS_MILLIS") == 0 )
			tf = formatter::JSON::TS_MILLIS;
		else if ( strcmp(json_timestamps.c_str(), "JSON::TS_ISO8601") == 0 )
			tf = formatter::JSON::TS_ISO8601;
		else
			{
			Error(Fmt("Invalid JSON timestamp format: %s", json_timestamps.c_str()));
			return false;
			}

		formatter = new formatter::JSON(this, tf);
		// Using JSON implicitly turns off the header meta fields.
		include_meta = false;
		}
	else
		{
		// Enable utf-8 if needed
		if ( enable_utf_8 )
			desc.EnableUTF8();

		// Use the default "Bro logs" format.
		desc.EnableEscaping();
		desc.AddEscapeSequence(separator);
		formatter::Ascii::SeparatorInfo sep_info(separator, set_separator, unset_field, empty_field);
		formatter = new formatter::Ascii(this, sep_info);
		}

	return true;
	}

Ascii::~Ascii()
	{
	if ( ! ascii_done )
		// In case of errors aborting the logging altogether,
		// DoFinish() may not have been called.
		CloseFile(network_time);

	delete formatter;
	}

bool Ascii::WriteHeaderField(const string& key, const string& val)
	{
	string str = meta_prefix + key + separator + val + "\n";

	return InternalWrite(fd, str.c_str(), str.length());
	}

void Ascii::CloseFile(double t)
	{
	if ( ! fd )
		return;

	if ( include_meta && ! tsv )
		WriteHeaderField("close", Timestamp(0));

	InternalClose(fd);
	fd = 0;
	gzfile = nullptr;
	}

bool Ascii::DoInit(const WriterInfo& info, int num_fields, const Field* const * fields)
	{
	assert(! fd);

	if ( ! init_options )
		return false;

	string path = info.path;

	if ( output_to_stdout )
		path = "/dev/stdout";

	fname = path;

	if ( ! IsSpecial(fname) )
		{
		std::string ext = "." + LogExt();

		if ( gzip_level > 0 )
			{
			ext += ".";
			ext += gzip_file_extension.empty() ? "gz" : gzip_file_extension;
			}

		fname += ext;

		bool use_shadow = zeek::Supervisor::ThisNode() && info.rotation_interval > 0;

		if ( use_shadow )
			{
			auto sfname = shadow_file_prefix + fname;
			auto sfd = open(sfname.data(), O_WRONLY | O_CREAT | O_TRUNC, 0666);

			if ( sfd < 0 )
				{
				Error(Fmt("cannot open %s: %s", sfname.data(), Strerror(errno)));
				return false;
				}

			safe_write(sfd, ext.data(), ext.size());
			safe_write(sfd, "\n", 1);

			auto ppf = info.post_proc_func;

			if ( ppf )
				safe_write(sfd, ppf, strlen(ppf));

			safe_write(sfd, "\n", 1);

			safe_close(sfd);
			}
		}

	fd = open(fname.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);

	if ( fd < 0 )
		{
		Error(Fmt("cannot open %s: %s", fname.c_str(),
			  Strerror(errno)));
		fd = 0;
		return false;
		}

	if ( gzip_level > 0 )
		{
		if ( gzip_level < 0 || gzip_level > 9 )
			{
			Error("invalid value for 'gzip_level', must be a number between 0 and 9.");
			return false;
			}

		char mode[4];
		snprintf(mode, sizeof(mode), "wb%d", gzip_level);
		errno = 0; // errno will only be set under certain circumstances by gzdopen.
		gzfile = gzdopen(fd, mode);

		if ( gzfile == nullptr )
			{
			Error(Fmt("cannot gzip %s: %s", fname.c_str(),
			                                Strerror(errno)));
			return false;
			}
		}
	else
		{
		gzfile = nullptr;
		}

	if ( ! WriteHeader(path) )
		{
		Error(Fmt("error writing to %s: %s", fname.c_str(), Strerror(errno)));
		return false;
		}

	return true;
	}

bool Ascii::WriteHeader(const string& path)
	{
	if ( ! include_meta )
		return true;

	string names;
	string types;

	for ( int i = 0; i < NumFields(); ++i )
		{
		if ( i > 0 )
			{
			names += separator;
			types += separator;
			}

		names += string(Fields()[i]->name);
		types += Fields()[i]->TypeName().c_str();
		}

	if ( tsv )
		{
		// A single TSV-style line is all we need.
		string str = names + "\n";
		if ( ! InternalWrite(fd, str.c_str(), str.length()) )
			return false;

		return true;
		}

	string str = meta_prefix
		+ "separator " // Always use space as separator here.
		+ get_escaped_string(separator, false)
		+ "\n";

	if ( ! InternalWrite(fd, str.c_str(), str.length()) )
		return false;

	if ( ! (WriteHeaderField("set_separator", get_escaped_string(set_separator, false)) &&
	        WriteHeaderField("empty_field", get_escaped_string(empty_field, false)) &&
	        WriteHeaderField("unset_field", get_escaped_string(unset_field, false)) &&
	        WriteHeaderField("path", get_escaped_string(path, false)) &&
	        WriteHeaderField("open", Timestamp(0))) )
		return false;

	if ( ! (WriteHeaderField("fields", names) &&
	        WriteHeaderField("types", types)) )
		return false;

	return true;
	}

bool Ascii::DoFlush(double network_time)
	{
	fsync(fd);
	return true;
	}

bool Ascii::DoFinish(double network_time)
	{
	if ( ascii_done )
		{
		fprintf(stderr, "internal error: duplicate finish\n");
		abort();
		}

	DoFlush(network_time);

	ascii_done = true;

	CloseFile(network_time);

	return true;
	}

bool Ascii::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{
	if ( ! fd )
		DoInit(Info(), NumFields(), Fields());

	desc.Clear();

	if ( ! formatter->Describe(&desc, num_fields, fields, vals) )
		return false;

	desc.AddRaw("\n", 1);

	const char* bytes = (const char*)desc.Bytes();
	int len = desc.Len();

	if ( strncmp(bytes, meta_prefix.data(), meta_prefix.size()) == 0 )
		{
		// It would so escape the first character.
		char hex[4] = {'\\', 'x', '0', '0'};
		bytetohex(bytes[0], hex + 2);

		if ( ! InternalWrite(fd, hex, 4) )
			goto write_error;

		++bytes;
		--len;
		}

	if ( ! InternalWrite(fd, bytes, len) )
		goto write_error;

        if ( ! IsBuf() )
		fsync(fd);

	return true;

write_error:
	Error(Fmt("error writing to %s: %s", fname.c_str(), Strerror(errno)));
	return false;
	}

bool Ascii::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	// Don't rotate special files or if there's not one currently open.
	if ( ! fd || IsSpecial(Info().path) )
		{
		FinishedRotation();
		return true;
		}

	CloseFile(close);

	string nname = string(rotated_path) + "." + LogExt();

	if ( gzip_level > 0 )
		{
		nname += ".";
		nname += gzip_file_extension.empty() ? "gz" : gzip_file_extension;
		}

	if ( rename(fname.c_str(), nname.c_str()) != 0 )
		{
		char buf[256];
		bro_strerror_r(errno, buf, sizeof(buf));
		Error(Fmt("failed to rename %s to %s: %s", fname.c_str(),
		          nname.c_str(), buf));
		FinishedRotation();
		return false;
		}

	bool use_shadow = zeek::Supervisor::ThisNode() && Info().rotation_interval > 0;

	if ( use_shadow )
		{
		auto sfname = shadow_file_prefix + fname;

		if ( unlink(sfname.data()) != 0 )
			{
			Error(Fmt("cannot unlink %s: %s", sfname.data(), Strerror(errno)));
			FinishedRotation();
			return false;
			}
		}

	if ( ! FinishedRotation(nname.c_str(), fname.c_str(), open, close, terminating) )
		{
		Error(Fmt("error rotating %s to %s", fname.c_str(), nname.c_str()));
		return false;
		}

	return true;
	}

bool Ascii::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

bool Ascii::DoHeartbeat(double network_time, double current_time)
	{
	// Nothing to do.
	return true;
	}

static std::vector<LeftoverLog> find_leftover_logs()
	{
	std::vector<LeftoverLog> rval;
	std::vector<std::string> stale_shadow_files;
	auto prefix_len = strlen(shadow_file_prefix);

	auto d = opendir(".");
	struct dirent* dp;

	while ( (dp = readdir(d)) )
		{
		if ( strncmp(dp->d_name, shadow_file_prefix, prefix_len) != 0 )
			continue;

		std::string log_name = dp->d_name + prefix_len;

		if ( is_file(log_name) )
			{
			if ( auto ll = parse_shadow_log(log_name) )
				{
				if ( ll->error.empty() )
					rval.emplace_back(std::move(*ll));
				else
					reporter->Error("failed to process leftover log '%s': %s",
					                log_name.data(), ll->error.data());
				}
			}
		else
			// There was a log here.  It's gone now.
			stale_shadow_files.emplace_back(dp->d_name);
		}

	for ( const auto& f : stale_shadow_files )
		if ( unlink(f.data()) != 0 )
			reporter->Error("cannot unlink %s: %s", f.data(), strerror(errno));

	closedir(d);
	return rval;
	}

void Ascii::RotateLeftoverLogs()
	{
	if ( ! zeek::Supervisor::ThisNode() )
		return;

	// Log file crash recovery: if there's still leftover shadow files from the
	// ASCII log writer, attempt to rotate their associated log file.  Ideally
	// may be better if the ASCII writer itself could implement the entire
	// crash recovery logic itself without being called from external, but (1)
	// this does need to get called from a particular point in the
	// initialization process (after zeek_init()) and (2) the nature of writers
	// being instantiated lazily means that trying to rotate a leftover log
	// only upon seeing that an open() will clobber something means they'll
	// possibly not be rotated in a timely manner (e.g. a log files that are
	// rarely written to).  So the logic below drives the entire leftover log
	// crash recovery process for a supervised node upon startup.
	auto leftover_logs = find_leftover_logs();

	for ( const auto& ll : leftover_logs )
		{
		static auto rot_info_type = zeek::id::find_type<zeek::RecordType>("Log::RotationInfo");
		static auto writer_type = zeek::id::find_type<zeek::EnumType>("Log::Writer");
		static auto writer_idx = writer_type->Lookup("Log", "WRITER_ASCII");
		static auto writer_val = writer_type->GetVal(writer_idx);
		static auto default_ppf = zeek::id::find_func("Log::__default_rotation_postprocessor");
		assert(default_ppf);

		auto ppf = default_ppf;

		if ( ! ll.post_proc_func.empty() )
			{
			auto func = zeek::id::find_func(ll.post_proc_func.data());

			if ( func )
				ppf = std::move(func);
			else
				reporter->Warning("Could no postprocess log '%s' with intended "
								  "postprocessor function '%s', proceeding "
								  " with the default function",
								  ll.filename.data(), ll.post_proc_func.data());
			}

		auto rotation_path = log_mgr->FormatRotationPath(
		        writer_val, ll.Name(), ll.open_time, ll.close_time, false, ppf);

		rotation_path += ll.extension;

		auto rot_info = zeek::make_intrusive<zeek::RecordVal>(rot_info_type);
		rot_info->Assign(0, writer_val);
		rot_info->Assign<zeek::StringVal>(1, rotation_path);
		rot_info->Assign<zeek::StringVal>(2, ll.Name());
		rot_info->Assign<zeek::TimeVal>(3, ll.open_time);
		rot_info->Assign<zeek::TimeVal>(4, ll.close_time);
		rot_info->Assign(5, zeek::val_mgr->False());

		if ( rename(ll.filename.data(), rotation_path.data()) != 0 )
			reporter->FatalError("Found leftover/unprocessed log '%s', but "
								 "failed to rotate it: %s",
								 ll.filename.data(), strerror(errno));

		if ( ! ll.DeleteShadow() )
			// Unusual failure to report, but not strictly fatal.
			reporter->Warning("Failed to unlink %s: %s",
			                  ll.shadow_filename.data(), strerror(errno));

		try
			{
			ppf->Invoke(std::move(rot_info));
			reporter->Info("Rotated/postprocessed leftover log '%s' -> '%s' ",
			               ll.filename.data(), rotation_path.data());
			}
		catch ( InterpreterException& e )
			{
			reporter->Warning("Postprocess function '%s' failed for leftover log '%s'",
			                  ppf->Name(), ll.filename.data());
			}
		}
	}

string Ascii::LogExt()
	{
	const char* ext = zeekenv("ZEEK_LOG_SUFFIX");

	if ( ! ext )
		ext = "log";

	return ext;
	}

string Ascii::Timestamp(double t)
	{
	time_t teatime = time_t(t);

	if ( ! teatime )
		{
		// Use wall clock.
		struct timeval tv;
		if ( gettimeofday(&tv, 0) < 0 )
			Error("gettimeofday failed");
		else
			teatime = tv.tv_sec;
		}

	struct tm tmbuf;
	struct tm* tm = localtime_r(&teatime, &tmbuf);

	char tmp[128];
	const char* const date_fmt = "%Y-%m-%d-%H-%M-%S";
	strftime(tmp, sizeof(tmp), date_fmt, tm);

	return tmp;
	}

bool Ascii::InternalWrite(int fd, const char* data, int len)
	{
	if ( ! gzfile )
		return safe_write(fd, data, len);

	while ( len > 0 )
		{
		int n = gzwrite(gzfile, data, len);

		if ( n <= 0 )
			{
			const char* err = gzerror(gzfile, &n);
			Error(Fmt("Ascii::InternalWrite error: %s\n", err));
			return false;
			}

		data += n;
		len -= n;
		}

	return true;
	}

bool Ascii::InternalClose(int fd)
	{
	if ( ! gzfile )
		{
		safe_close(fd);
		return true;
		}

	int res = gzclose(gzfile);

	if ( res == Z_OK )
		return true;

	switch ( res ) {
	case Z_STREAM_ERROR:
		Error("Ascii::InternalClose gzclose error: invalid file stream");
		break;
	case Z_BUF_ERROR:
		Error("Ascii::InternalClose gzclose error: "
		      "no compression progress possible during buffer flush");
		break;
	case Z_ERRNO:
		Error(Fmt("Ascii::InternalClose gzclose error: %s\n", Strerror(errno)));
		break;
	default:
		Error("Ascii::InternalClose invalid gzclose result");
		break;
	}

	return false;
	}

