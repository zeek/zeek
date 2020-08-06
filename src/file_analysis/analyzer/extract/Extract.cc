// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <fcntl.h>

#include "Extract.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

namespace zeek::file_analysis::detail {

Extract::Extract(zeek::RecordValPtr args, zeek::file_analysis::File* file,
                 const std::string& arg_filename, uint64_t arg_limit)
    : file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("EXTRACT"),
                              std::move(args), file),
      filename(arg_filename), limit(arg_limit), depth(0)
	{
	fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0666);

	if ( fd < 0 )
		{
		fd = 0;
		char buf[128];
		zeek::util::zeek_strerror_r(errno, buf, sizeof(buf));
		zeek::reporter->Error("cannot open %s: %s", filename.c_str(), buf);
		}
	}

Extract::~Extract()
	{
	if ( fd )
		zeek::util::safe_close(fd);
	}

static const zeek::ValPtr& get_extract_field_val(const zeek::RecordValPtr& args,
                                                 const char* name)
	{
	const auto& rval = args->GetField(name);

	if ( ! rval )
		zeek::reporter->Error("File extraction analyzer missing arg field: %s", name);

	return rval;
	}

zeek::file_analysis::Analyzer* Extract::Instantiate(zeek::RecordValPtr args,
                                                    zeek::file_analysis::File* file)
	{
	const auto& fname = get_extract_field_val(args, "extract_filename");
	const auto& limit = get_extract_field_val(args, "extract_limit");

	if ( ! fname || ! limit )
		return nullptr;

	return new Extract(std::move(args), file, fname->AsString()->CheckString(),
	                   limit->AsCount());
	}

static bool check_limit_exceeded(uint64_t lim, uint64_t depth, uint64_t len, uint64_t* n)
	{
	if ( lim == 0 )
		{
		*n = len;
		return false;
		}

	if ( depth >= lim )
		{
		*n = 0;
		return true;
		}
	else if ( depth + len > lim )
		{
		*n = lim - depth;
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
	if ( ! fd )
		return false;

	uint64_t towrite = 0;
	bool limit_exceeded = check_limit_exceeded(limit, depth, len, &towrite);

	if ( limit_exceeded && file_extraction_limit )
		{
		zeek::file_analysis::File* f = GetFile();
		f->FileEvent(file_extraction_limit, {
			f->ToVal(),
			GetArgs(),
			zeek::val_mgr->Count(limit),
			zeek::val_mgr->Count(len)
		});

		// Limit may have been modified by a BIF, re-check it.
		limit_exceeded = check_limit_exceeded(limit, depth, len, &towrite);
		}

	if ( towrite > 0 )
		{
		zeek::util::safe_write(fd, reinterpret_cast<const char*>(data), towrite);
		depth += towrite;
		}

	return ( ! limit_exceeded );
	}

bool Extract::Undelivered(uint64_t offset, uint64_t len)
	{
	if ( depth == offset )
		{
		char* tmp = new char[len]();
		zeek::util::safe_write(fd, tmp, len);
		delete [] tmp;
		depth += len;
		}

	return true;
	}

} // namespace zeek::file_analysis::detail
