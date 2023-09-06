// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/analyzer/extract/Extract.h"

#include <fcntl.h>
#include <string>

#include "zeek/Event.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/util.h"

namespace zeek::file_analysis::detail
	{

Extract::Extract(RecordValPtr args, file_analysis::File* file, const std::string& arg_filename,
                 uint64_t arg_limit, bool arg_limit_includes_missing)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("EXTRACT"), std::move(args), file),
	  filename(arg_filename), limit(arg_limit), written(0),
	  limit_includes_missing(arg_limit_includes_missing)
	{
	char buf[128];
	file_stream = fopen(filename.data(), "wb");

	if ( file_stream )
		{
		// Try to ensure full buffering.
		if ( util::detail::setvbuf(file_stream, nullptr, _IOFBF, BUFSIZ) )
			{
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Warning("cannot set buffering mode for %s: %s", filename.data(), buf);
			}
		}
	else
		{
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("cannot open %s: %s", filename.c_str(), buf);
		}
	}

Extract::~Extract()
	{
	if ( file_stream && fclose(file_stream) )
		{
		char buf[128];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("cannot close %s: %s", filename.data(), buf);
		}
	}

static ValPtr get_extract_field_val(const RecordValPtr& args, const char* name)
	{
	const auto& rval = args->GetField(name);

	if ( ! rval )
		reporter->Error("File extraction analyzer missing arg field: %s", name);

	return rval;
	}

file_analysis::Analyzer* Extract::Instantiate(RecordValPtr args, file_analysis::File* file)
	{
	const auto& fname = get_extract_field_val(args, "extract_filename");
	const auto& limit = get_extract_field_val(args, "extract_limit");
	const auto& extract_limit_includes_missing = get_extract_field_val(
		args, "extract_limit_includes_missing");

	if ( ! fname || ! limit || ! extract_limit_includes_missing )
		return nullptr;

	return new Extract(std::move(args), file, fname->AsString()->CheckString(), limit->AsCount(),
	                   extract_limit_includes_missing->AsBool());
	}

/**
 * Check if we are exceeding the write limit with this write.
 * @param lim size limit
 * @param written how many bytes we have written so far
 * @param len length of the write
 * @param n number of bytes to write to keep within limit
 * @returns true if limit exceeded
 */
static bool check_limit_exceeded(uint64_t lim, uint64_t written, uint64_t len, uint64_t* n)
	{
	if ( lim == 0 )
		{
		*n = len;
		return false;
		}

	if ( written >= lim )
		{
		*n = 0;
		return true;
		}
	else if ( written + len > lim )
		{
		*n = lim - written;
		return true;
		}
	else
		{
		*n = len;
		}

	return false;
	}

bool Extract::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! file_stream )
		return false;

	uint64_t towrite = 0;
	bool limit_exceeded = check_limit_exceeded(limit, written, len, &towrite);

	if ( limit_exceeded && file_extraction_limit )
		{
		file_analysis::File* f = GetFile();
		f->FileEvent(file_extraction_limit,
		             {f->ToVal(), GetArgs(), val_mgr->Count(limit), val_mgr->Count(len)});

		// Limit may have been modified by a BIF, re-check it.
		limit_exceeded = check_limit_exceeded(limit, written, len, &towrite);
		}

	char buf[128];

	if ( towrite > 0 )
		{
		if ( fwrite(data, towrite, 1, file_stream) != 1 )
			{
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("failed to write to extracted file %s: %s", filename.data(), buf);
			fclose(file_stream);
			file_stream = nullptr;
			return false;
			}

		written += towrite;
		}

	// Assume we may not try to write anything more for a while due to reaching
	// the extraction limit and the file analysis File still proceeding to
	// do other analysis without destructing/closing this one until the very end,
	// so flush anything currently buffered.
	if ( limit_exceeded && fflush(file_stream) )
		{
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Warning("cannot fflush extracted file %s: %s", filename.data(), buf);
		}

	return (! limit_exceeded);
	}

bool Extract::Undelivered(uint64_t offset, uint64_t len)
	{
	if ( ! file_stream )
		return false;

	if ( limit_includes_missing )
		{
		uint64_t towrite = 0;
		bool limit_exceeded = check_limit_exceeded(limit, written, len, &towrite);
		// if the limit is exceeded, we have to raise the event. This gives scripts the opportunity
		// to raise the limit.
		if ( limit_exceeded && file_extraction_limit )
			{
			file_analysis::File* f = GetFile();
			f->FileEvent(file_extraction_limit,
			             {f->ToVal(), GetArgs(), val_mgr->Count(limit), val_mgr->Count(len)});
			// we have to check again if the limit is still exceedee
			limit_exceeded = check_limit_exceeded(limit, written, len, &towrite);
			}

		// if the limit is exceeded, abort and don't do anything - no reason to seek.
		if ( limit_exceeded )
			return false;

		// if we don't skip holes, count this hole against the write limit
		written += len;
		}

	if ( fseek(file_stream, len + offset, SEEK_SET) != 0 )
		{
		char buf[128];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("failed to seek in extracted file %s: %s", filename.data(), buf);
		fclose(file_stream);
		file_stream = nullptr;
		return false;
		}

	return true;
	}

	} // namespace zeek::file_analysis::detail
