// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/Analyzer.h"

#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Manager.h"

#include "const.bif.netvar_h" // for max_analyzer_violations
#include "event.bif.netvar_h" // for analyzer_violation_info

namespace zeek::file_analysis
	{

ID Analyzer::id_counter = 0;

Analyzer::~Analyzer()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Destroy file analyzer %s", file_mgr->GetComponentName(tag).c_str());
	}

void Analyzer::SetAnalyzerTag(const zeek::Tag& arg_tag)
	{
	assert(! tag || tag == arg_tag);
	tag = arg_tag;
	}

Analyzer::Analyzer(zeek::Tag arg_tag, RecordValPtr arg_args, File* arg_file)
	: tag(arg_tag), args(std::move(arg_args)), file(arg_file), got_stream_delivery(false),
	  skip(false), analyzer_confirmed(false)
	{
	id = ++id_counter;
	}

Analyzer::Analyzer(RecordValPtr arg_args, File* arg_file)
	: Analyzer({}, std::move(arg_args), arg_file)
	{
	}

const char* Analyzer::GetAnalyzerName() const
	{
	assert(tag);
	return file_mgr->GetComponentName(tag).c_str();
	}

void Analyzer::AnalyzerConfirmation(zeek::Tag arg_tag)
	{
	if ( analyzer_confirmed )
		return;

	analyzer_confirmed = true;

	if ( ! analyzer_confirmation_info )
		return;

	static auto info_type = zeek::id::find_type<RecordType>("AnalyzerConfirmationInfo");
	static auto info_f_idx = info_type->FieldOffset("f");

	auto info = zeek::make_intrusive<RecordVal>(info_type);
	info->Assign(info_f_idx, GetFile()->ToVal());

	const auto& tval = arg_tag ? arg_tag.AsVal() : tag.AsVal();
	event_mgr.Enqueue(analyzer_confirmation_info, tval, info);
	}

void Analyzer::AnalyzerViolation(const char* reason, const char* data, int len, zeek::Tag arg_tag)
	{
	++analyzer_violations;

	if ( analyzer_violations > BifConst::max_analyzer_violations )
		{
		if ( analyzer_violations == BifConst::max_analyzer_violations + 1 )
			Weird("too_many_analyzer_violations");

		return;
		}

	if ( ! analyzer_violation_info )
		return;

	static auto info_type = zeek::id::find_type<RecordType>("AnalyzerViolationInfo");
	static auto info_reason_idx = info_type->FieldOffset("reason");
	static auto info_f_idx = info_type->FieldOffset("f");
	static auto info_data_idx = info_type->FieldOffset("data");

	auto info = zeek::make_intrusive<RecordVal>(info_type);
	info->Assign(info_reason_idx, make_intrusive<StringVal>(reason));
	info->Assign(info_f_idx, GetFile()->ToVal());
	if ( data && len )
		info->Assign(info_data_idx, make_intrusive<StringVal>(len, data));

	const auto& tval = arg_tag ? arg_tag.AsVal() : tag.AsVal();
	event_mgr.Enqueue(analyzer_violation_info, tval, info);
	}

void Analyzer::Weird(const char* name, const char* addl)
	{
	zeek::reporter->Weird(GetFile(), name, addl, GetAnalyzerName());
	}

	} // namespace zeek::file_analysis
