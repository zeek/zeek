// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Extract.h"
#include "util.h"

using namespace file_analysis;

Extract::Extract(RecordVal* args, File* file, const string& arg_filename)
    : file_analysis::Analyzer(args, file), filename(arg_filename)
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

file_analysis::Analyzer* Extract::Instantiate(RecordVal* args, File* file)
	{
	using BifType::Record::Files::AnalyzerArgs;
	Val* v = args->Lookup(AnalyzerArgs->FieldOffset("extract_filename"));

	if ( ! v )
		return 0;

	return new Extract(args, file, v->AsString()->CheckString());
	}

bool Extract::DeliverChunk(const u_char* data, uint64 len, uint64 offset)
	{
	if ( ! fd )
		return false;

	safe_pwrite(fd, data, len, offset);
	return true;
	}
