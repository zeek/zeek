// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "StringExtract.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

StringExtract::StringExtract(RecordVal* args, File* file, uint64 arg_limit,
                             const char* pre, const char* post,
                             EventHandlerPtr ev)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("STRINGEXTRACT"), args, file),
      limit(arg_limit), depth(0), bytes_given_to_preamble_matcher(0),
      bytes_given_to_postamble_matcher(0), match_state(LOOKING_FOR_PREAMBLE),
      preamble(new RE_Match_State_Range(pre)),
      postamble(new RE_Match_State_Range(post)),
      extracted_content(), event(ev)
	{
	}

StringExtract::~StringExtract()
	{
	delete preamble;
	delete postamble;
	}

static Val* get_extract_field_val(RecordVal* args, const char* name)
	{
	Val* rval = args->Lookup(name);

	if ( ! rval )
		reporter->Error("File string extraction analyzer missing arg field: %s",
		                name);

	return rval;
	}

file_analysis::Analyzer* StringExtract::Instantiate(RecordVal* args, File* file)
	{
	Val* limit = get_extract_field_val(args, "string_extract_limit");
	Val* pre = get_extract_field_val(args, "string_extract_preamble");
	Val* post = get_extract_field_val(args, "string_extract_postamble");
	Val* event = get_extract_field_val(args, "string_extract_event");

	if ( ! limit || ! pre || ! post || ! event )
		return 0;

	EventHandlerPtr ev = event_registry->Lookup(event->AsFunc()->Name());
	return new StringExtract(args, file, limit->AsCount(),
	                         pre->AsStringVal()->CheckString(),
	                         post->AsStringVal()->CheckString(), ev);
	}

void StringExtract::RaiseEvent(size_t len)
	{
	val_list* args = new val_list;
	args->append(GetFile()->GetVal()->Ref());
	args->append(new StringVal(new BroString(extracted_content.data(), len, 0)));
	mgr.QueueEvent(event, args);
	}

bool StringExtract::DeliverStream(const u_char* data, uint64 len)
	{
	if ( ! event ) return true;

	if ( match_state == LOOKING_FOR_PREAMBLE )
		{
		bool bol = bytes_given_to_preamble_matcher == 0 ? true : false;
		bool matched = preamble->Match(data, len, bol, false);
		bytes_given_to_preamble_matcher += len;

		if ( matched )
			{
			int end_idx_in_full_range = preamble->FirstMatchEndPos();
			uint64 end_idx_relative_to_last_input =
			        end_idx_in_full_range -
			        (bytes_given_to_preamble_matcher - len);
			uint64 offset_of_remaining_data = end_idx_relative_to_last_input + 1;
			match_state = LOOKING_FOR_POSTAMBLE;

			if ( offset_of_remaining_data < len - 1 )
				DeliverStream(data + offset_of_remaining_data,
				              len - offset_of_remaining_data);
			}
		}
	else
		{
		bool bol = bytes_given_to_postamble_matcher == 0 ? true : false;
		bool matched = postamble->Match(data, len, bol, false);
		bytes_given_to_postamble_matcher += len;

		if ( matched )
			{
			int begin_idx_in_full_range = postamble->FirstMatchBeginPos();
			int end_idx_in_full_range = postamble->FirstMatchEndPos();
			uint64 end_idx_relative_to_last_input =
			        end_idx_in_full_range -
			        (bytes_given_to_preamble_matcher - len);
			uint64 offset_of_remaining_data = end_idx_relative_to_last_input + 1;

			if ( begin_idx_in_full_range < extracted_content.size() )
				{
				// Extracted to much, use "first begin_idx_in_full_range" bytes
				// of the buffer.
				RaiseEvent(begin_idx_in_full_range);
				}
			else
				{
				uint64 remaining_extract_bytes =
				        begin_idx_in_full_range - extracted_content.size();

				if ( limit &&
				     extracted_content.size() + remaining_extract_bytes > limit )
					{
					uint64 bytes_left_to_extract = limit - extracted_content.size();
					extracted_content.insert(extracted_content.end(), data,
					                         data + bytes_left_to_extract);
					RaiseEvent(extracted_content.size());
					}
				else
					{
					extracted_content.insert(extracted_content.end(), data,
					                         data + remaining_extract_bytes);
					RaiseEvent(extracted_content.size());
					}
				}

			Reset();

			if ( offset_of_remaining_data < len - 1 )
				DeliverStream(data + offset_of_remaining_data,
				              len - offset_of_remaining_data);
			}
		else
			{
			if ( limit && extracted_content.size() + len > limit )
				{
				uint64 bytes_left_to_extract = limit - extracted_content.size();
				extracted_content.insert(extracted_content.end(), data,
				                         data + bytes_left_to_extract);
				RaiseEvent(extracted_content.size());
				Reset();
				data += bytes_left_to_extract;
				len -= bytes_left_to_extract;
				DeliverStream(data, len);
				}
			else
				extracted_content.insert(extracted_content.end(), data, data + len);
			}
		}

	return true;
	}

bool StringExtract::Undelivered(uint64 offset, uint64 len)
	{
	Reset();
	return true;
	}
