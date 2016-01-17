// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <algorithm>

#include "File.h"
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

static Val* empty_connection_table()
	{
	TypeList* tbl_index = new TypeList(conn_id);
	tbl_index->Append(conn_id->Ref());
	TableType* tbl_type = new TableType(tbl_index, connection_type->Ref());
	Val* rval = new TableVal(tbl_type);
	Unref(tbl_type);
	return rval;
	}

static RecordVal* get_conn_id_val(const Connection* conn)
	{
	RecordVal* v = new RecordVal(conn_id);
	v->Assign(0, new AddrVal(conn->OrigAddr()));
	v->Assign(1, new PortVal(ntohs(conn->OrigPort()), conn->ConnTransport()));
	v->Assign(2, new AddrVal(conn->RespAddr()));
	v->Assign(3, new PortVal(ntohs(conn->RespPort()), conn->ConnTransport()));
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

void File::StaticInit()
	{
	if ( id_idx != -1 )
		return;

	id_idx = Idx("id", fa_file_type);
	parent_id_idx = Idx("parent_id", fa_file_type);
	source_idx = Idx("source", fa_file_type);
	is_orig_idx = Idx("is_orig", fa_file_type);
	conns_idx = Idx("conns", fa_file_type);
	last_active_idx = Idx("last_active", fa_file_type);
	seen_bytes_idx = Idx("seen_bytes", fa_file_type);
	total_bytes_idx = Idx("total_bytes", fa_file_type);
	missing_bytes_idx = Idx("missing_bytes", fa_file_type);
	overflow_bytes_idx = Idx("overflow_bytes", fa_file_type);
	timeout_interval_idx = Idx("timeout_interval", fa_file_type);
	bof_buffer_size_idx = Idx("bof_buffer_size", fa_file_type);
	bof_buffer_idx = Idx("bof_buffer", fa_file_type);
	meta_mime_type_idx = Idx("mime_type", fa_metadata_type);
	meta_mime_types_idx = Idx("mime_types", fa_metadata_type);
	}

File::File(const string& file_id, const string& source_name, Connection* conn,
           analyzer::Tag tag, bool is_orig)
	: id(file_id), val(0), file_reassembler(0), stream_offset(0),
	  reassembly_max_buffer(0), did_metadata_inference(false),
	  reassembly_enabled(false), postpone_timeout(false), done(false),
	  analyzers(this)
	{
	StaticInit();

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Creating new File object", file_id.c_str());

	val = new RecordVal(fa_file_type);
	val->Assign(id_idx, new StringVal(file_id.c_str()));
	SetSource(source_name);

	if ( conn )
		{
		val->Assign(is_orig_idx, new Val(is_orig, TYPE_BOOL));
		UpdateConnectionFields(conn, is_orig);
		}

	UpdateLastActivityTime();
	}

File::~File()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Destroying File object", id.c_str());
	Unref(val);
	delete file_reassembler;
	}

void File::UpdateLastActivityTime()
	{
	val->Assign(last_active_idx, new Val(network_time, TYPE_TIME));
	}

double File::GetLastActivityTime() const
	{
	return val->Lookup(last_active_idx)->AsTime();
	}

bool File::UpdateConnectionFields(Connection* conn, bool is_orig)
	{
	if ( ! conn )
		return false;

	Val* conns = val->Lookup(conns_idx);

	if ( ! conns )
		{
		conns = empty_connection_table();
		val->Assign(conns_idx, conns);
		}

	Val* idx = get_conn_id_val(conn);

	if ( conns->AsTableVal()->Lookup(idx) )
		{
		Unref(idx);
		return false;
		}

	conns->AsTableVal()->Assign(idx, conn->BuildConnVal());
	Unref(idx);
	return true;
	}

void File::RaiseFileOverNewConnection(Connection* conn, bool is_orig)
	{
	if ( conn && FileEventAvailable(file_over_new_connection) )
		{
		val_list* vl = new val_list();
		vl->append(val->Ref());
		vl->append(conn->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		FileEvent(file_over_new_connection, vl);
		}
	}

uint64 File::LookupFieldDefaultCount(int idx) const
	{
	Val* v = val->LookupWithDefault(idx);
	uint64 rval = v->AsCount();
	Unref(v);
	return rval;
	}

double File::LookupFieldDefaultInterval(int idx) const
	{
	Val* v = val->LookupWithDefault(idx);
	double rval = v->AsInterval();
	Unref(v);
	return rval;
	}

int File::Idx(const string& field, const RecordType* type)
	{
	int rval = type->FieldOffset(field.c_str());

	if ( rval < 0 )
		reporter->InternalError("Unknown %s field: %s", type->GetName().c_str(),
		                        field.c_str());

	return rval;
	}

string File::GetSource() const
	{
	Val* v = val->Lookup(source_idx);

	return v ? v->AsString()->CheckString() : string();
	}

void File::SetSource(const string& source)
	{
	val->Assign(source_idx, new StringVal(source.c_str()));
	}

double File::GetTimeoutInterval() const
	{
	return LookupFieldDefaultInterval(timeout_interval_idx);
	}

void File::SetTimeoutInterval(double interval)
	{
	val->Assign(timeout_interval_idx, new Val(interval, TYPE_INTERVAL));
	}

bool File::SetExtractionLimit(RecordVal* args, uint64 bytes)
	{
	Analyzer* a = analyzers.Find(file_mgr->GetComponentTag("EXTRACT"), args);

	if ( ! a )
		return false;

	Extract* e = dynamic_cast<Extract*>(a);

	if ( ! e )
		return false;

	e->SetLimit(bytes);
	return true;
	}

void File::IncrementByteCount(uint64 size, int field_idx)
	{
	uint64 old = LookupFieldDefaultCount(field_idx);
	val->Assign(field_idx, new Val(old + size, TYPE_COUNT));
	}

void File::SetTotalBytes(uint64 size)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Total bytes %" PRIu64, id.c_str(), size);
	val->Assign(total_bytes_idx, new Val(size, TYPE_COUNT));
	}

bool File::IsComplete() const
	{
	Val* total = val->Lookup(total_bytes_idx);
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

bool File::AddAnalyzer(file_analysis::Tag tag, RecordVal* args)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Queuing addition of %s analyzer",
		id.c_str(), file_mgr->GetComponentName(tag).c_str());

	if ( done )
		return false;

	return analyzers.QueueAdd(tag, args) != 0;
	}

bool File::RemoveAnalyzer(file_analysis::Tag tag, RecordVal* args)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Queuing remove of %s analyzer",
		id.c_str(), file_mgr->GetComponentName(tag).c_str());

	return done ? false : analyzers.QueueRemove(tag, args);
	}

void File::EnableReassembly()
	{
	reassembly_enabled = true;
	}

void File::DisableReassembly()
	{
	reassembly_enabled = false;
	delete file_reassembler;
	file_reassembler = 0;
	}

void File::SetReassemblyBuffer(uint64 max)
	{
	reassembly_max_buffer = max;
	}

void File::InferMetadata()
	{
	did_metadata_inference = true;

	Val* bof_buffer_val = val->Lookup(bof_buffer_idx);

	if ( ! bof_buffer_val )
		{
		if ( bof_buffer.size == 0 )
			return;

		BroString* bs = concatenate(bof_buffer.chunks);
		bof_buffer_val = new StringVal(bs);
		val->Assign(bof_buffer_idx, bof_buffer_val);
		}

	if ( ! FileEventAvailable(file_sniff) )
		return;

	RuleMatcher::MIME_Matches matches;
	const u_char* data = bof_buffer_val->AsString()->Bytes();
	uint64 len = bof_buffer_val->AsString()->Len();
	len = min(len, LookupFieldDefaultCount(bof_buffer_size_idx));
	file_mgr->DetectMIME(data, len, &matches);

	val_list* vl = new val_list();
	vl->append(val->Ref());
	RecordVal* meta = new RecordVal(fa_metadata_type);
	vl->append(meta);

	if ( ! matches.empty() )
		{
		meta->Assign(meta_mime_type_idx,
		             new StringVal(*(matches.begin()->second.begin())));
		meta->Assign(meta_mime_types_idx,
		             file_analysis::GenMIMEMatchesVal(matches));
		}

	FileEvent(file_sniff, vl);
	return;
	}

bool File::BufferBOF(const u_char* data, uint64 len)
	{
	if ( bof_buffer.full )
		return false;

	uint64 desired_size = LookupFieldDefaultCount(bof_buffer_size_idx);

	bof_buffer.chunks.push_back(new BroString(data, len, 0));
	bof_buffer.size += len;

	if ( bof_buffer.size < desired_size )
		return true;

	bof_buffer.full = true;

	if ( bof_buffer.size > 0 )
		{
		BroString* bs = concatenate(bof_buffer.chunks);
		val->Assign(bof_buffer_idx, new StringVal(bs));
		}

	return false;
	}

void File::DeliverStream(const u_char* data, uint64 len)
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
	        fmt_bytes((const char*) data, min((uint64)40, len)),
	        len > 40 ? "..." : "");

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->GotStreamDelivery() )
			{
			int num_bof_chunks_behind = bof_buffer.chunks.size();

			if ( ! bof_was_full )
				// We just added a chunk to the BOF buffer, don't count it
				// as it will get delivered on its own.
				num_bof_chunks_behind -= 1;

			uint64 bytes_delivered = 0;

			// Catch this analyzer up with the BOF buffer.
			for ( int i = 0; i < num_bof_chunks_behind; ++i )
				{
				if ( ! a->DeliverStream(bof_buffer.chunks[i]->Bytes(),
				                        bof_buffer.chunks[i]->Len()) )
					analyzers.QueueRemove(a->Tag(), a->Args());

				bytes_delivered += bof_buffer.chunks[i]->Len();
				}

			a->SetGotStreamDelivery();
			// May need to catch analyzer up on missed gap?
			// Analyzer should be fully caught up to stream_offset now.
			}

		if ( ! a->DeliverStream(data, len) )
			analyzers.QueueRemove(a->Tag(), a->Args());
		}

	stream_offset += len;
	IncrementByteCount(len, seen_bytes_idx);
	}

void File::DeliverChunk(const u_char* data, uint64 len, uint64 offset)
	{
	// Potentially handle reassembly and deliver to the stream analyzers.
	if ( file_reassembler )
		{
		if ( reassembly_max_buffer > 0 &&
		     reassembly_max_buffer < file_reassembler->TotalSize() )
			{
			uint64 current_offset = stream_offset;
			uint64 gap_bytes = file_reassembler->Flush();
			IncrementByteCount(gap_bytes, overflow_bytes_idx);

			if ( FileEventAvailable(file_reassembly_overflow) )
				{
				val_list* vl = new val_list();
				vl->append(val->Ref());
				vl->append(new Val(current_offset, TYPE_COUNT));
				vl->append(new Val(gap_bytes, TYPE_COUNT));
				FileEvent(file_reassembly_overflow, vl);
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
	        fmt_bytes((const char*) data, min((uint64)40, len)),
	        len > 40 ? "..." : "");

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->DeliverChunk(data, len, offset) )
			{
			analyzers.QueueRemove(a->Tag(), a->Args());
			}
		}

	if ( IsComplete() )
		EndOfFile();
	}

void File::DataIn(const u_char* data, uint64 len, uint64 offset)
	{
	analyzers.DrainModifications();
	DeliverChunk(data, len, offset);
	analyzers.DrainModifications();
	}

void File::DataIn(const u_char* data, uint64 len)
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

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->EndOfFile() )
			analyzers.QueueRemove(a->Tag(), a->Args());
		}

	FileEvent(file_state_remove);

	analyzers.DrainModifications();
	}

void File::Gap(uint64 offset, uint64 len)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Gap of size %" PRIu64 " at offset %," PRIu64,
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

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->Undelivered(offset, len) )
			analyzers.QueueRemove(a->Tag(), a->Args());
		}

	if ( FileEventAvailable(file_gap) )
		{
		val_list* vl = new val_list();
		vl->append(val->Ref());
		vl->append(new Val(offset, TYPE_COUNT));
		vl->append(new Val(len, TYPE_COUNT));
		FileEvent(file_gap, vl);
		}

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

	val_list* vl = new val_list();
	vl->append(val->Ref());
	FileEvent(h, vl);
	}

void File::FileEvent(EventHandlerPtr h, val_list* vl)
	{
	mgr.QueueEvent(h, vl);

	if ( h == file_new || h == file_over_new_connection ||
	     h == file_sniff ||
	     h == file_timeout || h == file_extraction_limit )
		{
		// immediate feedback is required for these events.
		mgr.Drain();
		analyzers.DrainModifications();
		}
	}
