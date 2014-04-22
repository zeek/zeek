// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Extract.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Extract::Extract(RecordVal* args, File* file, const string& arg_filename,
                 uint64 arg_limit)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("EXTRACT"), args, file),
      filename(arg_filename), limit(arg_limit)
	{
	fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);

	if ( fd < 0 )
		{
		fd = 0;
		char buf[128];
		strerror_r(errno, buf, sizeof(buf));
		reporter->Error("cannot open %s: %s", filename.c_str(), buf);
		}
	}

Extract::~Extract()
	{
	if ( fd )
		safe_close(fd);
	}

static Val* get_extract_field_val(RecordVal* args, const char* name)
	{
	Val* rval = args->Lookup(name);

	if ( ! rval )
		reporter->Error("File extraction analyzer missing arg field: %s", name);

	return rval;
	}

file_analysis::Analyzer* Extract::Instantiate(RecordVal* args, File* file)
	{
	Val* fname = get_extract_field_val(args, "extract_filename");
	Val* limit = get_extract_field_val(args, "extract_limit");

	if ( ! fname || ! limit )
		return 0;

	return new Extract(args, file, fname->AsString()->CheckString(),
	                   limit->AsCount());
	}

static bool check_limit_exceeded(uint64 lim, uint64 off, uint64 len, uint64* n)
	{
	if ( lim == 0 )
		{
		*n = len;
		return false;
		}

	if ( off >= lim )
		{
		*n = 0;
		return true;
		}

	*n = lim - off;

	if ( len > *n )
		return true;
	else
		*n = len;

	return false;
	}

bool Extract::DeliverChunk(const u_char* data, uint64 len, uint64 offset)
	{
	if ( ! fd )
		return false;

	uint64 towrite = 0;
	bool limit_exceeded = check_limit_exceeded(limit, offset, len, &towrite);

	if ( limit_exceeded && file_extraction_limit )
		{
		File* f = GetFile();
		val_list* vl = new val_list();
		vl->append(f->GetVal()->Ref());
		vl->append(Args()->Ref());
		vl->append(new Val(limit, TYPE_COUNT));
		vl->append(new Val(offset, TYPE_COUNT));
		vl->append(new Val(len, TYPE_COUNT));
		f->FileEvent(file_extraction_limit, vl);

		// Limit may have been modified by BIF, re-check it.
		limit_exceeded = check_limit_exceeded(limit, offset, len, &towrite);
		}

	if ( towrite > 0 )
		safe_pwrite(fd, data, towrite, offset);

	return ( ! limit_exceeded );
	}
