#include <string>

#include "Extract.h"
#include "util.h"

using namespace file_analysis;

Extract::Extract(Info* arg_info, const string& arg_filename)
    : Action(arg_info, BifEnum::FileAnalysis::ACTION_EXTRACT),
      filename(arg_filename)
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

Action* Extract::Instantiate(const RecordVal* args, Info* info)
	{
	const char* field = "extract_filename";
	int off = BifType::Record::FileAnalysis::ActionArgs->FieldOffset(field);
	Val* v = args->Lookup(off);

	if ( ! v ) return 0;

	return new Extract(info, v->AsString()->CheckString());
	}

bool Extract::DeliverChunk(const u_char* data, uint64 len, uint64 offset)
	{
	Action::DeliverChunk(data, len, offset);

	if ( ! fd ) return false;

	safe_pwrite(fd, data, len, offset);
	return true;
	}
