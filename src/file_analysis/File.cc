// See the file "COPYING" in the main distribution directory for copyright.

#include "File.h"

#include <utility>

#include "FileReassembler.h"
#include "FileTimer.h"
#include "Analyzer.h"
#include "Manager.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include "Event.h"
#include "RuleMatcher.h"

#include "analyzer/Analyzer.h"
#include "analyzer/Manager.h"

#include "analyzer/extract/Extract.h"

using namespace file_analysis;

static zeek::TableValPtr empty_connection_table()
	{
	auto tbl_index = zeek::make_intrusive<zeek::TypeList>(zeek::id::conn_id);
	tbl_index->Append(zeek::id::conn_id);
	auto tbl_type = zeek::make_intrusive<zeek::TableType>(std::move(tbl_index),
	                                                        zeek::id::connection);
	return zeek::make_intrusive<zeek::TableVal>(std::move(tbl_type));
	}

static zeek::RecordValPtr get_conn_id_val(const Connection* conn)
	{
	auto v = zeek::make_intrusive<zeek::RecordVal>(zeek::id::conn_id);
	v->Assign(0, zeek::make_intrusive<zeek::AddrVal>(conn->OrigAddr()));
	v->Assign(1, zeek::val_mgr->Port(ntohs(conn->OrigPort()), conn->ConnTransport()));
	v->Assign(2, zeek::make_intrusive<zeek::AddrVal>(conn->RespAddr()));
	v->Assign(3, zeek::val_mgr->Port(ntohs(conn->RespPort()), conn->ConnTransport()));
	return v;
	}

int File::id_idx = -1;
int File::parent_id_idx = -1;
int File::source_idx = -1;
int File::is_orig_idx = -1;
int File::conns_idx = -1;
int File::last_active_idx = -1;
int File::seen_bytes_idx = -1;
int File::total_bytes_idx = -1;
int File::missing_bytes_idx = -1;
int File::overflow_bytes_idx = -1;
int File::timeout_interval_idx = -1;
int File::bof_buffer_size_idx = -1;
int File::bof_buffer_idx = -1;
int File::meta_mime_type_idx = -1;
int File::meta_mime_types_idx = -1;
int File::meta_inferred_idx = -1;

void File::StaticInit()
	{
	if ( id_idx != -1 )
		return;

	id_idx = Idx("id", zeek::id::fa_file);
	parent_id_idx = Idx("parent_id", zeek::id::fa_file);
	source_idx = Idx("source", zeek::id::fa_file);
	is_orig_idx = Idx("is_orig", zeek::id::fa_file);
	conns_idx = Idx("conns", zeek::id::fa_file);
	last_active_idx = Idx("last_active", zeek::id::fa_file);
	seen_bytes_idx = Idx("seen_bytes", zeek::id::fa_file);
	total_bytes_idx = Idx("total_bytes", zeek::id::fa_file);
	missing_bytes_idx = Idx("missing_bytes", zeek::id::fa_file);
	overflow_bytes_idx = Idx("overflow_bytes", zeek::id::fa_file);
	timeout_interval_idx = Idx("timeout_interval", zeek::id::fa_file);
	bof_buffer_size_idx = Idx("bof_buffer_size", zeek::id::fa_file);
	bof_buffer_idx = Idx("bof_buffer", zeek::id::fa_file);
	meta_mime_type_idx = Idx("mime_type", zeek::id::fa_metadata);
	meta_mime_types_idx = Idx("mime_types", zeek::id::fa_metadata);
	meta_inferred_idx = Idx("inferred", zeek::id::fa_metadata);
	}

File::File(const std::string& file_id, const std::string& source_name, Connection* conn,
           zeek::analyzer::Tag tag, bool is_orig)
	: id(file_id), val(nullptr), file_reassembler(nullptr), stream_offset(0),
	  reassembly_max_buffer(0), did_metadata_inference(false),
	  reassembly_enabled(false), postpone_timeout(false), done(false),
	  analyzers(this)
	{
	StaticInit();

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Creating new File object", file_id.c_str());

	val = zeek::make_intrusive<zeek::RecordVal>(zeek::id::fa_file);
	val->Assign(id_idx, zeek::make_intrusive<zeek::StringVal>(file_id.c_str()));
	SetSource(source_name);

	if ( conn )
		{
		val->Assign(is_orig_idx, zeek::val_mgr->Bool(is_orig));
		UpdateConnectionFields(conn, is_orig);
		}

	UpdateLastActivityTime();
	}

File::~File()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Destroying File object", id.c_str());
	delete file_reassembler;

	for ( auto a : done_analyzers )
		delete a;
	}

void File::UpdateLastActivityTime()
	{
	val->Assign(last_active_idx, zeek::make_intrusive<zeek::TimeVal>(network_time));
	}

double File::GetLastActivityTime() const
	{
	return val->GetField(last_active_idx)->AsTime();
	}

bool File::UpdateConnectionFields(Connection* conn, bool is_orig)
	{
	if ( ! conn )
		return false;

	zeek::Val* conns = val->GetField(conns_idx).get();

	if ( ! conns )
		{
		auto ect = empty_connection_table();
		conns = ect.get();
		val->Assign(conns_idx, std::move(ect));
		}

	auto idx = get_conn_id_val(conn);

	if ( conns->AsTableVal()->FindOrDefault(idx) )
		return false;

	conns->AsTableVal()->Assign(std::move(idx), conn->ConnVal());
	return true;
	}

void File::RaiseFileOverNewConnection(Connection* conn, bool is_orig)
	{
	if ( conn && FileEventAvailable(file_over_new_connection) )
		{
		FileEvent(file_over_new_connection, {
			val,
			conn->ConnVal(),
			zeek::val_mgr->Bool(is_orig),
		});
		}
	}

uint64_t File::LookupFieldDefaultCount(int idx) const
	{
	auto v = val->GetFieldOrDefault(idx);
	return v->AsCount();
	}

double File::LookupFieldDefaultInterval(int idx) const
	{
	auto v = val->GetFieldOrDefault(idx);
	return v->AsInterval();
	}

int File::Idx(const std::string& field, const zeek::RecordType* type)
	{
	int rval = type->FieldOffset(field.c_str());

	if ( rval < 0 )
		reporter->InternalError("Unknown %s field: %s", type->GetName().c_str(),
		                        field.c_str());

	return rval;
	}

std::string File::GetSource() const
	{
	const auto& v = val->GetField(source_idx);

	return v ? v->AsString()->CheckString() : std::string();
	}

void File::SetSource(const std::string& source)
	{
	val->Assign(source_idx, zeek::make_intrusive<zeek::StringVal>(source.c_str()));
	}

double File::GetTimeoutInterval() const
	{
	return LookupFieldDefaultInterval(timeout_interval_idx);
	}

void File::SetTimeoutInterval(double interval)
	{
	val->Assign(timeout_interval_idx, zeek::make_intrusive<zeek::IntervalVal>(interval));
	}

bool File::SetExtractionLimit(zeek::RecordVal* args, uint64_t bytes)
	{ return SetExtractionLimit({zeek::NewRef{}, args}, bytes); }

bool File::SetExtractionLimit(zeek::RecordValPtr args, uint64_t bytes)
	{
	Analyzer* a = analyzers.Find(file_mgr->GetComponentTag("EXTRACT"),
	                             std::move(args));

	if ( ! a )
		return false;

	Extract* e = dynamic_cast<Extract*>(a);

	if ( ! e )
		return false;

	e->SetLimit(bytes);
	return true;
	}

void File::IncrementByteCount(uint64_t size, int field_idx)
	{
	uint64_t old = LookupFieldDefaultCount(field_idx);
	val->Assign(field_idx, zeek::val_mgr->Count(old + size));
	}

void File::SetTotalBytes(uint64_t size)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Total bytes %" PRIu64, id.c_str(), size);
	val->Assign(total_bytes_idx, zeek::val_mgr->Count(size));
	}

bool File::IsComplete() const
	{
	const auto& total = val->GetField(total_bytes_idx);

	if ( ! total )
		return false;

	if ( stream_offset >= total->AsCount() )
		return true;

	return false;
	}

void File::ScheduleInactivityTimer() const
	{
	timer_mgr->Add(new FileTimer(network_time, id, GetTimeoutInterval()));
	}

bool File::AddAnalyzer(file_analysis::Tag tag, zeek::RecordVal* args)
	{ return AddAnalyzer(tag, {zeek::NewRef{}, args}); }

bool File::AddAnalyzer(file_analysis::Tag tag, zeek::RecordValPtr args)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Queuing addition of %s analyzer",
		id.c_str(), file_mgr->GetComponentName(tag).c_str());

	if ( done )
		return false;

	return analyzers.QueueAdd(tag, std::move(args)) != nullptr;
	}

bool File::RemoveAnalyzer(file_analysis::Tag tag, zeek::RecordVal* args)
	{ return RemoveAnalyzer(tag, {zeek::NewRef{}, args}); }

bool File::RemoveAnalyzer(file_analysis::Tag tag, zeek::RecordValPtr args)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Queuing remove of %s analyzer",
		id.c_str(), file_mgr->GetComponentName(tag).c_str());

	return done ? false : analyzers.QueueRemove(tag, std::move(args));
	}

void File::EnableReassembly()
	{
	reassembly_enabled = true;
	}

void File::DisableReassembly()
	{
	reassembly_enabled = false;
	delete file_reassembler;
	file_reassembler = nullptr;
	}

void File::SetReassemblyBuffer(uint64_t max)
	{
	reassembly_max_buffer = max;
	}

bool File::SetMime(const std::string& mime_type)
	{
	if ( mime_type.empty() || bof_buffer.size != 0 || did_metadata_inference )
		return false;

	did_metadata_inference = true;
	bof_buffer.full = true;

	if ( ! FileEventAvailable(file_sniff) )
		return false;

	auto meta = zeek::make_intrusive<zeek::RecordVal>(zeek::id::fa_metadata);
	meta->Assign(meta_mime_type_idx, zeek::make_intrusive<zeek::StringVal>(mime_type));
	meta->Assign(meta_inferred_idx, zeek::val_mgr->False());

	FileEvent(file_sniff, {val, std::move(meta)});
	return true;
	}

void File::InferMetadata()
	{
	did_metadata_inference = true;

	zeek::Val* bof_buffer_val = val->GetField(bof_buffer_idx).get();

	if ( ! bof_buffer_val )
		{
		if ( bof_buffer.size == 0 )
			return;

		zeek::String* bs = concatenate(bof_buffer.chunks);
		val->Assign<zeek::StringVal>(bof_buffer_idx, bs);
		bof_buffer_val = val->GetField(bof_buffer_idx).get();
		}

	if ( ! FileEventAvailable(file_sniff) )
		return;

	RuleMatcher::MIME_Matches matches;
	const u_char* data = bof_buffer_val->AsString()->Bytes();
	uint64_t len = bof_buffer_val->AsString()->Len();
	len = std::min(len, LookupFieldDefaultCount(bof_buffer_size_idx));
	file_mgr->DetectMIME(data, len, &matches);

	auto meta = zeek::make_intrusive<zeek::RecordVal>(zeek::id::fa_metadata);

	if ( ! matches.empty() )
		{
		meta->Assign<zeek::StringVal>(meta_mime_type_idx,
		                        *(matches.begin()->second.begin()));
		meta->Assign(meta_mime_types_idx,
		             file_analysis::GenMIMEMatchesVal(matches));
		}

	FileEvent(file_sniff, {val, std::move(meta)});
	}

bool File::BufferBOF(const u_char* data, uint64_t len)
	{
	if ( bof_buffer.full )
		return false;

	uint64_t desired_size = LookupFieldDefaultCount(bof_buffer_size_idx);

	bof_buffer.chunks.push_back(new zeek::String(data, len, false));
	bof_buffer.size += len;

	if ( bof_buffer.size < desired_size )
		return true;

	bof_buffer.full = true;

	if ( bof_buffer.size > 0 )
		{
		zeek::String* bs = concatenate(bof_buffer.chunks);
		val->Assign(bof_buffer_idx, zeek::make_intrusive<zeek::StringVal>(bs));
		}

	return false;
	}

void File::DeliverStream(const u_char* data, uint64_t len)
	{
	bool bof_was_full = bof_buffer.full;
	// Buffer enough data for the BOF buffer
	BufferBOF(data, len);

	if ( ! did_metadata_inference && bof_buffer.full &&
	     LookupFieldDefaultCount(missing_bytes_idx) == 0 )
		InferMetadata();

	DBG_LOG(DBG_FILE_ANALYSIS,
	        "[%s] %" PRIu64 " stream bytes in at offset %" PRIu64 "; %s [%s%s]",
	        id.c_str(), len, stream_offset,
	        IsComplete() ? "complete" : "incomplete",
	        fmt_bytes((const char*) data, std::min((uint64_t)40, len)),
	        len > 40 ? "..." : "");

	file_analysis::Analyzer* a = nullptr;
	zeek::IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "stream delivery to analyzer %s", file_mgr->GetComponentName(a->Tag()).c_str());
		if ( ! a->GotStreamDelivery() )
			{
			DBG_LOG(DBG_FILE_ANALYSIS, "skipping stream delivery to analyzer %s", file_mgr->GetComponentName(a->Tag()).c_str());
			int num_bof_chunks_behind = bof_buffer.chunks.size();

			if ( ! bof_was_full )
				// We just added a chunk to the BOF buffer, don't count it
				// as it will get delivered on its own.
				num_bof_chunks_behind -= 1;

			uint64_t bytes_delivered = 0;

			// Catch this analyzer up with the BOF buffer.
			for ( int i = 0; i < num_bof_chunks_behind; ++i )
				{
				if ( ! a->Skipping() )
					{
					if ( ! a->DeliverStream(bof_buffer.chunks[i]->Bytes(),
								bof_buffer.chunks[i]->Len()) )
						{
						a->SetSkip(true);
						analyzers.QueueRemove(a->Tag(), a->GetArgs());
						}
					}

				bytes_delivered += bof_buffer.chunks[i]->Len();
				}

			a->SetGotStreamDelivery();
			// May need to catch analyzer up on missed gap?
			// Analyzer should be fully caught up to stream_offset now.
			}

		if ( ! a->Skipping() )
			{
			if ( ! a->DeliverStream(data, len) )
				{
				a->SetSkip(true);
				analyzers.QueueRemove(a->Tag(), a->GetArgs());
				}
			}
		}

	stream_offset += len;
	IncrementByteCount(len, seen_bytes_idx);
	}

void File::DeliverChunk(const u_char* data, uint64_t len, uint64_t offset)
	{
	// Potentially handle reassembly and deliver to the stream analyzers.
	if ( file_reassembler )
		{
		if ( reassembly_max_buffer > 0 &&
		     reassembly_max_buffer < file_reassembler->TotalSize() )
			{
			uint64_t current_offset = stream_offset;
			uint64_t gap_bytes = file_reassembler->Flush();
			IncrementByteCount(gap_bytes, overflow_bytes_idx);

			if ( FileEventAvailable(file_reassembly_overflow) )
				{
				FileEvent(file_reassembly_overflow, {
					val,
					zeek::val_mgr->Count(current_offset),
					zeek::val_mgr->Count(gap_bytes)
				});
				}
			}

		// Forward data to the reassembler.
		file_reassembler->NewBlock(network_time, offset, len, data);
		}
	else if ( stream_offset == offset )
		{
		// This is the normal case where a file is transferred linearly.
		// Nothing special should be done here.
		DeliverStream(data, len);
		}
	else if ( reassembly_enabled )
		{
		// This is data that doesn't match the offset and the reassembler
		// needs to be enabled.
		file_reassembler = new FileReassembler(this, stream_offset);
		file_reassembler->NewBlock(network_time, offset, len, data);
		}
	else
		{
		// We can't reassemble so we throw out the data for streaming.
		IncrementByteCount(len, overflow_bytes_idx);
		}

	DBG_LOG(DBG_FILE_ANALYSIS,
	        "[%s] %" PRIu64 " chunk bytes in at offset %" PRIu64 "; %s [%s%s]",
	        id.c_str(), len, offset,
	        IsComplete() ? "complete" : "incomplete",
	        fmt_bytes((const char*) data, std::min((uint64_t)40, len)),
	        len > 40 ? "..." : "");

	file_analysis::Analyzer* a = nullptr;
	zeek::IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "chunk delivery to analyzer %s", file_mgr->GetComponentName(a->Tag()).c_str());
		if ( ! a->Skipping() )
			{
			if ( ! a->DeliverChunk(data, len, offset) )
				{
				a->SetSkip(true);
				analyzers.QueueRemove(a->Tag(), a->GetArgs());
				}
			}
		}

	if ( IsComplete() )
		EndOfFile();
	}

void File::DoneWithAnalyzer(Analyzer* analyzer)
	{
	done_analyzers.push_back(analyzer);
	}

void File::DataIn(const u_char* data, uint64_t len, uint64_t offset)
	{
	analyzers.DrainModifications();
	DeliverChunk(data, len, offset);
	analyzers.DrainModifications();
	}

void File::DataIn(const u_char* data, uint64_t len)
	{
	analyzers.DrainModifications();
	DeliverChunk(data, len, stream_offset);
	analyzers.DrainModifications();
	}

void File::EndOfFile()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] End of file", id.c_str());

	if ( done )
		return;

	if ( file_reassembler )
		{
		file_reassembler->Flush();
		}

	// Mark the bof_buffer as full in case it isn't yet
	// so that the whole thing can be flushed out to
	// any stream analyzers.
	if ( ! bof_buffer.full )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "[%s] File over but bof_buffer not full.", id.c_str());
		bof_buffer.full = true;
		DeliverStream((const u_char*) "", 0);
		}
	analyzers.DrainModifications();

	done = true;

	file_analysis::Analyzer* a = nullptr;
	zeek::IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->EndOfFile() )
			analyzers.QueueRemove(a->Tag(), a->GetArgs());
		}

	FileEvent(file_state_remove);

	analyzers.DrainModifications();
	}

void File::Gap(uint64_t offset, uint64_t len)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Gap of size %" PRIu64 " at offset %" PRIu64,
		id.c_str(), len, offset);

	if ( file_reassembler && ! file_reassembler->IsCurrentlyFlushing() )
		{
		file_reassembler->FlushTo(offset + len);
		// The reassembler will call us back with all the gaps we need to know.
		return;
		}

	if ( ! bof_buffer.full )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "[%s] File gap before bof_buffer filled, continued without attempting to fill bof_buffer.", id.c_str());
		bof_buffer.full = true;
		DeliverStream((const u_char*) "", 0);
		}

	file_analysis::Analyzer* a = nullptr;
	zeek::IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->Undelivered(offset, len) )
			analyzers.QueueRemove(a->Tag(), a->GetArgs());
		}

	if ( FileEventAvailable(file_gap) )
		FileEvent(file_gap, {val, zeek::val_mgr->Count(offset), zeek::val_mgr->Count(len)});

	analyzers.DrainModifications();

	stream_offset += len;
	IncrementByteCount(len, missing_bytes_idx);
	}

bool File::FileEventAvailable(EventHandlerPtr h)
	{
	return h && ! file_mgr->IsIgnored(id);
	}

void File::FileEvent(EventHandlerPtr h)
	{
	if ( ! FileEventAvailable(h) )
		return;

	FileEvent(h, zeek::Args{val});
	}

void File::FileEvent(EventHandlerPtr h, val_list* vl)
	{
	FileEvent(h, zeek::val_list_to_args(*vl));
	delete vl;
	}

void File::FileEvent(EventHandlerPtr h, val_list vl)
	{
	FileEvent(h, zeek::val_list_to_args(vl));
	}

void File::FileEvent(EventHandlerPtr h, zeek::Args args)
	{
	mgr.Enqueue(h, std::move(args));

	if ( h == file_new || h == file_over_new_connection ||
	     h == file_sniff ||
	     h == file_timeout || h == file_extraction_limit )
		{
		// immediate feedback is required for these events.
		mgr.Drain();
		analyzers.DrainModifications();
		}
	}

bool File::PermitWeird(const char* name, uint64_t threshold, uint64_t rate,
                       double duration)
	{
	return ::PermitWeird(weird_state, name, threshold, rate, duration);
	}
