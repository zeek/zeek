#include <string>

#include "Info.h"
#include "InfoTimer.h"
#include "FileID.h"
#include "Manager.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"

using namespace file_analysis;

static TableVal* empty_conn_id_set()
	{
	TypeList* set_index = new TypeList(conn_id);
	set_index->Append(conn_id->Ref());
	return new TableVal(new SetType(set_index, 0));
	}

static StringVal* get_conn_uid_val(Connection* conn)
	{
	char tmp[20];
	if ( ! conn->GetUID() )
		conn->SetUID(calculate_unique_id());
    return new StringVal(uitoa_n(conn->GetUID(), tmp, sizeof(tmp), 62));
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

int Info::file_id_idx = -1;
int Info::parent_file_id_idx = -1;
int Info::protocol_idx = -1;
int Info::conn_uids_idx = -1;
int Info::conn_ids_idx = -1;
int Info::seen_bytes_idx = -1;
int Info::total_bytes_idx = -1;
int Info::missing_bytes_idx = -1;
int Info::overflow_bytes_idx = -1;
int Info::timeout_interval_idx = -1;
int Info::bof_buffer_size_idx = -1;
int Info::bof_buffer_idx = -1;
int Info::file_type_idx = -1;
int Info::mime_type_idx = -1;
int Info::actions_idx = -1;

void Info::InitFieldIndices()
	{
	if ( file_id_idx != -1 ) return;
	file_id_idx = Idx("file_id");
	parent_file_id_idx = Idx("parent_file_id");
	protocol_idx = Idx("protocol");
	conn_uids_idx = Idx("conn_uids");
	conn_ids_idx = Idx("conn_ids");
	seen_bytes_idx = Idx("seen_bytes");
	total_bytes_idx = Idx("total_bytes");
	missing_bytes_idx = Idx("missing_bytes");
	overflow_bytes_idx = Idx("overflow_bytes");
	timeout_interval_idx = Idx("timeout_interval");
	bof_buffer_size_idx = Idx("bof_buffer_size");
	bof_buffer_idx = Idx("bof_buffer");
	file_type_idx = Idx("file_type");
	mime_type_idx = Idx("mime_type");
	actions_idx = Idx("actions");
	}

Info::Info(const string& unique, Connection* conn, const string& protocol)
    : file_id(unique), unique(unique), val(0), last_activity_time(network_time),
      postpone_timeout(false), need_reassembly(false), done(false),
      actions(this)
	{
	InitFieldIndices();

	char id[20];
	uitoa_n(calculate_unique_id(), id, sizeof(id), 62);

	DBG_LOG(DBG_FILE_ANALYSIS, "Creating new Info object %s", id);

	val = new RecordVal(BifType::Record::FileAnalysis::Info);
	val->Assign(file_id_idx, new StringVal(id));
	file_id = FileID(id);

	UpdateConnectionFields(conn);

	if ( protocol != "" )
		val->Assign(protocol_idx, new StringVal(protocol.c_str()));
	}

Info::~Info()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Destroying Info object %s", file_id.c_str());
	Unref(val);
	}

void Info::UpdateConnectionFields(Connection* conn)
	{
	if ( ! conn ) return;

	Val* conn_uids = val->Lookup(conn_uids_idx);
	Val* conn_ids = val->Lookup(conn_ids_idx);
	if ( ! conn_uids )
		val->Assign(conn_uids_idx, conn_uids = new TableVal(string_set));
	if ( ! conn_ids )
		val->Assign(conn_ids_idx, conn_ids = empty_conn_id_set());

	conn_uids->AsTableVal()->Assign(get_conn_uid_val(conn), 0);
	conn_ids->AsTableVal()->Assign(get_conn_id_val(conn), 0);
	}

uint64 Info::LookupFieldDefaultCount(int idx) const
	{
	Val* v = val->LookupWithDefault(idx);
	uint64 rval = v->AsCount();
	Unref(v);
	return rval;
	}

double Info::LookupFieldDefaultInterval(int idx) const
	{
	Val* v = val->LookupWithDefault(idx);
	double rval = v->AsInterval();
	Unref(v);
	return rval;
	}

int Info::Idx(const string& field)
	{
	int rval = BifType::Record::FileAnalysis::Info->FieldOffset(field.c_str());
	if ( rval < 0 )
		reporter->InternalError("Unkown FileAnalysis::Info field: %s",
		                        field.c_str());
	return rval;
	}

double Info::GetTimeoutInterval() const
	{
	return LookupFieldDefaultInterval(timeout_interval_idx);
	}

RecordVal* Info::GetResults(RecordVal* args) const
	{
	TableVal* actions_table = val->Lookup(actions_idx)->AsTableVal();
	RecordVal* rval = actions_table->Lookup(args)->AsRecordVal();

	if ( ! rval )
		{
		rval = new RecordVal(BifType::Record::FileAnalysis::ActionResults);
		actions_table->Assign(args, rval);
		}

	return rval;
	}

void Info::IncrementByteCount(uint64 size, int field_idx)
	{
	uint64 old = LookupFieldDefaultCount(field_idx);
	val->Assign(field_idx, new Val(old + size, TYPE_COUNT));
	}

void Info::SetTotalBytes(uint64 size)
	{
	val->Assign(total_bytes_idx, new Val(size, TYPE_COUNT));
	}

bool Info::IsComplete() const
	{
	Val* total = val->Lookup(total_bytes_idx);
	if ( ! total ) return false;
	if ( LookupFieldDefaultCount(seen_bytes_idx) >= total->AsCount() )
		return true;
	return false;
	}

void Info::ScheduleInactivityTimer() const
	{
	timer_mgr->Add(new InfoTimer(network_time, file_id, GetTimeoutInterval()));
	}

bool Info::AddAction(RecordVal* args)
	{
	return done ? false : actions.QueueAddAction(args);
	}

bool Info::RemoveAction(const RecordVal* args)
	{
	return done ? false : actions.QueueRemoveAction(args);
	}

bool Info::BufferBOF(const u_char* data, uint64 len)
	{
	if ( bof_buffer.full || bof_buffer.replayed ) return false;

	using BifEnum::FileAnalysis::TRIGGER_BOF;
	using BifEnum::FileAnalysis::TRIGGER_BOF_BUFFER;

	if ( bof_buffer.chunks.size() == 0 )
		Manager::EvaluatePolicy(TRIGGER_BOF, this);

	if ( ! data )
		{
		// A gap means we're done seeing as much as the start of the file
		// as possible, replay anything that we have
		bof_buffer.full = true;
		ReplayBOF();
		// TODO: libmagic stuff
		return false;
		}

	uint64 desired_size = LookupFieldDefaultCount(bof_buffer_size_idx);

	// If no buffer is desired or if the first chunk satisfies desired size,
	// just do everything we need with the first chunk without copying.
	if ( desired_size == 0 ||
	     (bof_buffer.chunks.empty() && len >= desired_size) )
		{
		bof_buffer.full = bof_buffer.replayed = true;
		val->Assign(bof_buffer_idx, new StringVal(new BroString(data, len, 0)));
		Manager::EvaluatePolicy(TRIGGER_BOF_BUFFER, this);
		// TODO: libmagic stuff
		return false;
		}

	bof_buffer.chunks.push_back(new BroString(data, len, 0));
	bof_buffer.size += len;

	if ( bof_buffer.size >= desired_size )
		{
		bof_buffer.full = true;
		// TODO: libmagic stuff
		ReplayBOF();
		}

	return true;
	}

void Info::ReplayBOF()
	{
	if ( bof_buffer.replayed ) return;
	bof_buffer.replayed = true;

	val->Assign(bof_buffer_idx, new StringVal(concatenate(bof_buffer.chunks)));

	using BifEnum::FileAnalysis::TRIGGER_BOF_BUFFER;
	Manager::EvaluatePolicy(TRIGGER_BOF_BUFFER, this);

	for ( size_t i = 0; i < bof_buffer.chunks.size(); ++i )
		DataIn(bof_buffer.chunks[i]->Bytes(), bof_buffer.chunks[i]->Len());
	}

void Info::DataIn(const u_char* data, uint64 len, uint64 offset)
	{
	actions.FlushQueuedModifications();
	// TODO: attempt libmagic stuff here before doing reassembly?

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->DeliverChunk(data, len, offset) )
			actions.QueueRemoveAction(act->Args());
		}

	actions.FlushQueuedModifications();

	// TODO: check reassembly requirement based on buffer size in record
	if ( need_reassembly )
		{
		// TODO
		}

	// TODO: reassembly overflow stuff, increment overflow count, eval trigger

	IncrementByteCount(len, seen_bytes_idx);
	}

void Info::DataIn(const u_char* data, uint64 len)
	{
	actions.FlushQueuedModifications();
	if ( BufferBOF(data, len) ) return;

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

	actions.FlushQueuedModifications();
	IncrementByteCount(len, seen_bytes_idx);
	}

void Info::EndOfFile()
	{
	if ( done ) return;
	done = true;
	actions.FlushQueuedModifications();

	// send along anything that's been buffered, but never flushed
	ReplayBOF();

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->EndOfFile() )
			actions.QueueRemoveAction(act->Args());
		}

	actions.FlushQueuedModifications();
	}

void Info::Gap(uint64 offset, uint64 len)
	{
	actions.FlushQueuedModifications();
	if ( BufferBOF(0, len) ) return;

	Action* act = 0;
	IterCookie* c = actions.InitForIteration();

	while ( (act = actions.NextEntry(c)) )
		{
		if ( ! act->Undelivered(offset, len) )
			actions.QueueRemoveAction(act->Args());
		}

	actions.FlushQueuedModifications();
	IncrementByteCount(len, missing_bytes_idx);
	}
