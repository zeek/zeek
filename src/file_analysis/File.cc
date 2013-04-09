#include <string>
#include <openssl/md5.h>

#include "File.h"
#include "FileTimer.h"
#include "FileID.h"
#include "Manager.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include "Analyzer.h"
#include "Event.h"

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
int File::conns_idx = -1;
int File::last_active_idx = -1;
int File::seen_bytes_idx = -1;
int File::total_bytes_idx = -1;
int File::missing_bytes_idx = -1;
int File::overflow_bytes_idx = -1;
int File::timeout_interval_idx = -1;
int File::bof_buffer_size_idx = -1;
int File::bof_buffer_idx = -1;
int File::file_type_idx = -1;
int File::mime_type_idx = -1;

magic_t File::magic = 0;
magic_t File::magic_mime = 0;

string File::salt;

void File::StaticInit()
	{
	if ( id_idx != -1 ) return;

	id_idx = Idx("id");
	parent_id_idx = Idx("parent_id");
	source_idx = Idx("source");
	conns_idx = Idx("conns");
	last_active_idx = Idx("last_active");
	seen_bytes_idx = Idx("seen_bytes");
	total_bytes_idx = Idx("total_bytes");
	missing_bytes_idx = Idx("missing_bytes");
	overflow_bytes_idx = Idx("overflow_bytes");
	timeout_interval_idx = Idx("timeout_interval");
	bof_buffer_size_idx = Idx("bof_buffer_size");
	bof_buffer_idx = Idx("bof_buffer");
	file_type_idx = Idx("file_type");
	mime_type_idx = Idx("mime_type");

	bro_init_magic(&magic, MAGIC_NONE);
	bro_init_magic(&magic_mime, MAGIC_MIME);

	salt = BifConst::FileAnalysis::salt->CheckString();
	}

File::File(const string& unique, Connection* conn, AnalyzerTag::Tag tag)
    : id(""), unique(unique), val(0), postpone_timeout(false),
      first_chunk(true), need_type(false), need_reassembly(false), done(false),
      actions(this)
	{
	StaticInit();

	char tmp[20];
	uint64 hash[2];
	string msg(unique + salt);
	MD5(reinterpret_cast<const u_char*>(msg.data()), msg.size(),
	    reinterpret_cast<u_char*>(hash));
	uitoa_n(hash[0], tmp, sizeof(tmp), 62);

	DBG_LOG(DBG_FILE_ANALYSIS, "Creating new File object %s (%s)", tmp,
	        unique.c_str());

	val = new RecordVal(fa_file_type);
	val->Assign(id_idx, new StringVal(tmp));
	id = FileID(tmp);

	if ( conn )
		{
		// add source and connection fields
		val->Assign(source_idx, new StringVal(Analyzer::GetTagName(tag)));
		UpdateConnectionFields(conn);
		}
	else
		// use the unique file handle as source
		val->Assign(source_idx, new StringVal(unique.c_str()));

	UpdateLastActivityTime();
	}

File::~File()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Destroying File object %s", id.c_str());
	Unref(val);
	}

void File::UpdateLastActivityTime()
	{
	val->Assign(last_active_idx, new Val(network_time, TYPE_TIME));
	}

double File::GetLastActivityTime() const
	{
	return val->Lookup(last_active_idx)->AsTime();
	}

void File::UpdateConnectionFields(Connection* conn)
	{
	if ( ! conn ) return;

	Val* conns = val->Lookup(conns_idx);

	bool is_first = false;

	if ( ! conns )
		{
		is_first = true;
		val->Assign(conns_idx, conns = empty_connection_table());
		}

	Val* idx = get_conn_id_val(conn);
	if ( ! conns->AsTableVal()->Lookup(idx) )
		{
		conns->AsTableVal()->Assign(idx, conn->BuildConnVal());
		if ( ! is_first )
			file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_NEW_CONN,
			                         this);
		}

	Unref(idx);
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

int File::Idx(const string& field)
	{
	int rval = fa_file_type->FieldOffset(field.c_str());
	if ( rval < 0 )
		reporter->InternalError("Unknown fa_file field: %s", field.c_str());
	return rval;
	}

double File::GetTimeoutInterval() const
	{
	return LookupFieldDefaultInterval(timeout_interval_idx);
	}

void File::IncrementByteCount(uint64 size, int field_idx)
	{
	uint64 old = LookupFieldDefaultCount(field_idx);
	val->Assign(field_idx, new Val(old + size, TYPE_COUNT));
	}

void File::SetTotalBytes(uint64 size)
	{
	val->Assign(total_bytes_idx, new Val(size, TYPE_COUNT));
	}

bool File::IsComplete() const
	{
	Val* total = val->Lookup(total_bytes_idx);
	if ( ! total ) return false;
	if ( LookupFieldDefaultCount(seen_bytes_idx) >= total->AsCount() )
		return true;
	return false;
	}

void File::ScheduleInactivityTimer() const
	{
	timer_mgr->Add(new FileTimer(network_time, id, GetTimeoutInterval()));
	}

bool File::AddAction(RecordVal* args)
	{
	return done ? false : actions.QueueAddAction(args);
	}

bool File::RemoveAction(const RecordVal* args)
	{
	return done ? false : actions.QueueRemoveAction(args);
	}

bool File::BufferBOF(const u_char* data, uint64 len)
	{
	if ( bof_buffer.full || bof_buffer.replayed ) return false;

	if ( bof_buffer.chunks.size() == 0 )
		file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_BOF, this);

	uint64 desired_size = LookupFieldDefaultCount(bof_buffer_size_idx);

	/* Leaving out this optimization (I think) for now to keep things simpler.
	// If first chunk satisfies desired size, do everything now without copying.
	if ( bof_buffer.chunks.empty() && len >= desired_size )
		{
		bof_buffer.full = bof_buffer.replayed = true;
		val->Assign(bof_buffer_idx, new StringVal(new BroString(data, len, 0)));
		file_mgr->EvaluatePolicy(TRIGGER_BOF_BUFFER, this);
		// TODO: libmagic stuff
		return false;
		}
	*/

	bof_buffer.chunks.push_back(new BroString(data, len, 0));
	bof_buffer.size += len;

	if ( bof_buffer.size >= desired_size )
		{
		bof_buffer.full = true;
		ReplayBOF();
		}

	return true;
	}

bool File::DetectTypes(const u_char* data, uint64 len)
	{
	const char* desc = bro_magic_buffer(magic, data, len);
	const char* mime = bro_magic_buffer(magic_mime, data, len);

	if ( desc )
		val->Assign(file_type_idx, new StringVal(desc));

	if ( mime )
		val->Assign(mime_type_idx, new StringVal(mime));

	return desc || mime;
	}

void File::ReplayBOF()
	{
	if ( bof_buffer.replayed ) return;
	bof_buffer.replayed = true;

	if ( bof_buffer.chunks.empty() )
		{
		// Since we missed the beginning, try file type detect on next data in.
		need_type = true;
		return;
		}

	BroString* bs = concatenate(bof_buffer.chunks);
	val->Assign(bof_buffer_idx, new StringVal(bs));
	bool have_type = DetectTypes(bs->Bytes(), bs->Len());

	using BifEnum::FileAnalysis::TRIGGER_BOF_BUFFER;
	file_mgr->EvaluatePolicy(TRIGGER_BOF_BUFFER, this);

	if ( have_type )
		file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TYPE, this);

	for ( size_t i = 0; i < bof_buffer.chunks.size(); ++i )
		DataIn(bof_buffer.chunks[i]->Bytes(), bof_buffer.chunks[i]->Len());
	}

void File::DataIn(const u_char* data, uint64 len, uint64 offset)
	{
	actions.DrainModifications();

	if ( first_chunk )
		{
		if ( DetectTypes(data, len) )
			{
			file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TYPE, this);
			actions.DrainModifications();
			}

		first_chunk = false;
		}

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->DeliverChunk(data, len, offset) )
			actions.QueueRemoveAction(act->Args());
		}

	actions.DrainModifications();

	// TODO: check reassembly requirement based on buffer size in record
	if ( need_reassembly )
		{
		// TODO
		}

	// TODO: reassembly overflow stuff, increment overflow count, eval trigger

	IncrementByteCount(len, seen_bytes_idx);
	}

void File::DataIn(const u_char* data, uint64 len)
	{
	actions.DrainModifications();

	if ( BufferBOF(data, len) ) return;

	if ( need_type )
		{
		if ( DetectTypes(data, len) )
			{
			file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TYPE, this);
			actions.DrainModifications();
			}

		need_type = false;
		}

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->DeliverStream(data, len) )
			{
			actions.QueueRemoveAction(act->Args());
			continue;
			}

		uint64 offset = LookupFieldDefaultCount(seen_bytes_idx) +
		                LookupFieldDefaultCount(missing_bytes_idx);

		if ( ! act->DeliverChunk(data, len, offset) )
			actions.QueueRemoveAction(act->Args());
		}

	actions.DrainModifications();
	IncrementByteCount(len, seen_bytes_idx);
	}

void File::EndOfFile()
	{
	if ( done ) return;

	actions.DrainModifications();

	// Send along anything that's been buffered, but never flushed.
	ReplayBOF();

	done = true;

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->EndOfFile() )
			actions.QueueRemoveAction(act->Args());
		}

	file_mgr->FileEvent(file_state_remove, this);

	actions.DrainModifications();
	}

void File::Gap(uint64 offset, uint64 len)
	{
	actions.DrainModifications();

	// If we were buffering the beginning of the file, a gap means we've got
	// as much contiguous stuff at the beginning as possible, so work with that.
	ReplayBOF();

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->Undelivered(offset, len) )
			actions.QueueRemoveAction(act->Args());
		}

	file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_GAP, this);

	actions.DrainModifications();
	IncrementByteCount(len, missing_bytes_idx);
	}
