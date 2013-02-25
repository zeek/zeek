#include <string>

#include "Extract.h"
#include "util.h"

using namespace file_analysis;

Extract::Extract(RecordVal* args, Info* info, const string& arg_filename)
    : Action(args, info), filename(arg_filename)
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

Action* Extract::Instantiate(RecordVal* args, Info* info)
	{
	using BifType::Record::FileAnalysis::ActionArgs;
	const char* field = "extract_filename";
	Val* v = args->Lookup(ActionArgs->FieldOffset(field));

	if ( ! v ) return 0;

	return new Extract(args, info, v->AsString()->CheckString());
	}

bool Extract::DeliverChunk(const u_char* data, uint64 len, uint64 offset)
	{
	Action::DeliverChunk(data, len, offset);

	if ( ! fd ) return false;

	safe_pwrite(fd, data, len, offset);
	return true;
	}
