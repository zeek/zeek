#include <vector>

#include "FileAnalysisManager.h"
#include "util.h"

using namespace file_analysis;

// keep in order w/ declared enum values in file_analysis.bif
static ActionInstantiator action_factory[] = {
	Extract::Instantiate,
};

Action::Action(Info* arg_info) : info(arg_info)
	{
	}

Extract::Extract(Info* arg_info, const string& arg_filename)
    : Action(arg_info), filename(arg_filename)
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

void Extract::DeliverChunk(const u_char* data, uint64 len, uint64 offset)
	{
	Action::DeliverChunk(data, len, offset);

	if ( ! fd ) return;

	safe_pwrite(fd, data, len, offset);
	}

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
int Info::actions_idx = -1;
int Info::action_args_idx = -1;

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
	actions_idx = Idx("actions");
	action_args_idx = Idx("action_args");
	}

Info::Info(const string& file_id, Connection* conn, const string& protocol)
    : val(0), last_activity_time(network_time), postpone_timeout(false),
      need_reassembly(false)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Creating new Info object %s", file_id.c_str());

	InitFieldIndices();

	val = new RecordVal(BifType::Record::FileAnalysis::Info);
	// TODO: hash/prettify file_id for script layer presentation
	val->Assign(file_id_idx, new StringVal(file_id.c_str()));

	UpdateConnectionFields(conn);

	if ( protocol != "" )
		val->Assign(protocol_idx, new StringVal(protocol.c_str()));

	ScheduleInactivityTimer();
	}

Info::~Info()
	{
	ActionMap::const_iterator it;
	for ( it = actions.begin(); it != actions.end(); ++it )
		delete it->second;

	DBG_LOG(DBG_FILE_ANALYSIS, "Destroying Info object %s", FileID().c_str());
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

double Info::TimeoutInterval() const
	{
	return LookupFieldDefaultInterval(timeout_interval_idx);
	}

string Info::FileID() const
	{
	return val->Lookup(file_id_idx)->AsString()->CheckString();
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
	timer_mgr->Add(new InfoTimer(network_time, FileID(), TimeoutInterval()));
	}

bool Info::AddAction(EnumVal* act, RecordVal* args)
	{
	if ( actions.find(act->AsEnum()) != actions.end() ) return false;

	Action* a = action_factory[act->AsEnum()](args, this);

	if ( ! a ) return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Add action %d for file id %s", act->AsEnum(),
	        FileID().c_str());
	actions[act->AsEnum()] = a;

	VectorVal* av = val->LookupWithDefault(actions_idx)->AsVectorVal();
	VectorVal* aav = val->LookupWithDefault(action_args_idx)->AsVectorVal();

	av->Assign(av->Size(), act->Ref(), 0);
	aav->Assign(aav->Size(), args->Ref(), 0);

	Unref(av);
	Unref(aav);

	return true;
	}

bool Info::RemoveAction(EnumVal* act)
	{
	ActionMap::iterator it = actions.find(act->AsEnum());

	if ( it == actions.end() ) return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove action %d for file id %s", act->AsEnum(),
	        FileID().c_str());
	delete it->second;
	actions.erase(it);
	return true;
	}

void Info::DataIn(const u_char* data, uint64 len, uint64 offset)
	{
	ActionMap::const_iterator it;
	for ( it = actions.begin(); it != actions.end(); ++it )
		it->second->DeliverChunk(data, len, offset);

	// TODO: check reassembly requirement based on buffer size in record
	if ( ! need_reassembly ) return;

	// TODO: reassembly stuff, possibly having to deliver chunks if buffer full
	//       and incrememt overflow bytes

	IncrementByteCount(len, seen_bytes_idx);
	}

void Info::DataIn(const u_char* data, uint64 len)
	{
	ActionMap::const_iterator it;
	for ( it = actions.begin(); it != actions.end(); ++it )
		{
		it->second->DeliverStream(data, len);
		uint64 offset = LookupFieldDefaultCount(seen_bytes_idx) +
		                LookupFieldDefaultCount(missing_bytes_idx);
		it->second->DeliverChunk(data, len, offset);
		}

	IncrementByteCount(len, seen_bytes_idx);
	}

void Info::EndOfFile()
	{
	ActionMap::const_iterator it;
	for ( it = actions.begin(); it != actions.end(); ++it )
		it->second->EndOfFile();
	}

void Info::Gap(uint64 offset, uint64 len)
	{
	ActionMap::const_iterator it;
	for ( it = actions.begin(); it != actions.end(); ++it )
		it->second->Undelivered(offset, len);

	IncrementByteCount(len, missing_bytes_idx);
	}

void InfoTimer::Dispatch(double t, int is_expire)
	{
	Info* info = file_mgr->Lookup(file_id);

	if ( ! info ) return;

	double last_active = info->LastActivityTime();
	double inactive_time = t > last_active ? t - last_active : 0.0;

	DBG_LOG(DBG_FILE_ANALYSIS, "Checking inactivity for %s, last active at %f, "
		    "inactive for %f", file_id.c_str(), last_active, inactive_time);

	if ( last_active == 0.0 )
		{
		// was created when network_time was zero, so re-schedule w/ valid time
		info->UpdateLastActivityTime();
		info->ScheduleInactivityTimer();
		return;
		}

	if ( inactive_time >= info->TimeoutInterval() )
		file_mgr->Timeout(file_id);
	else if ( ! is_expire )
		info->ScheduleInactivityTimer();
	}

Manager::Manager()
	{
	}

Manager::~Manager()
	{
	Terminate();
	}

void Manager::Terminate()
	{
	vector<string> keys;
	for ( FileMap::iterator it = file_map.begin(); it != file_map.end(); ++it )
		keys.push_back(it->first);
	for ( size_t i = 0; i < keys.size(); ++i )
		Timeout(keys[i], true);
	}

static void check_file_done(Info* info)
	{
	if ( info->IsComplete() )
		{
		Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_DONE, info);
		file_mgr->RemoveFile(info->FileID());
		}
	}

void Manager::DataIn(const string& file_id, const u_char* data, uint64 len,
                     uint64 offset, Connection* conn, const string& protocol)
	{
	Info* info = IDtoInfo(file_id, conn, protocol);
	info->DataIn(data, len, offset);
	check_file_done(info);
	}

void Manager::DataIn(const string& file_id, const u_char* data, uint64 len,
                     Connection* conn, const string& protocol)
	{
	Info* info = IDtoInfo(file_id, conn, protocol);
	info->DataIn(data, len);
	check_file_done(info);
	}

void Manager::EndOfFile(const string& file_id, Connection* conn,
                        const string& protocol)
	{
	Info* info = IDtoInfo(file_id, conn, protocol);
	info->EndOfFile();
	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_EOF, info);
	}

void Manager::Gap(const string& file_id, uint64 offset, uint64 len,
                  Connection* conn, const string& protocol)
	{
	Info* info = IDtoInfo(file_id, conn, protocol);
	info->Gap(offset, len);
	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_GAP, info);
	}

void Manager::SetSize(const string& file_id, uint64 size,
                      Connection* conn, const string& protocol)
	{
	Info* info = IDtoInfo(file_id, conn, protocol);
	info->SetTotalBytes(size);
	check_file_done(info);
	}

void Manager::EvaluatePolicy(BifEnum::FileAnalysis::Trigger t, Info* info)
	{
	const ID* id = global_scope()->Lookup("FileAnalysis::policy");
	assert(id);
	const Func* hook = id->ID_Val()->AsFunc();

	val_list vl(2);
	vl.append(new EnumVal(t, BifType::Enum::FileAnalysis::Trigger));
	vl.append(info->val->Ref());

	info->postpone_timeout = false;

	Val* result = hook->Call(&vl);
	Unref(result);
	}

bool Manager::PostponeTimeout(const string& file_id) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	info->postpone_timeout = true;
	return true;
	}

bool Manager::AddAction(const string& file_id, EnumVal* act,
                        RecordVal* args) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->AddAction(act, args);
	}

bool Manager::RemoveAction(const string& file_id, EnumVal* act) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->RemoveAction(act);
	}

Info* Manager::IDtoInfo(const string& file_id, Connection* conn,
                        const string& protocol)
	{
	Info* rval = file_map[file_id];

	if ( ! rval )
		{
		rval = file_map[file_id] = new Info(file_id, conn, protocol);
		Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_NEW, rval);
		}
	else
		{
		rval->UpdateLastActivityTime();
		rval->UpdateConnectionFields(conn);
		}

	return rval;
	}

Info* Manager::Lookup(const string& file_id) const
	{
	FileMap::const_iterator it = file_map.find(file_id);

	if ( it == file_map.end() ) return 0;

	return it->second;
	}

void Manager::Timeout(const string& file_id, bool is_terminating)
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return;

	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TIMEOUT, info);

	if ( info->postpone_timeout && ! is_terminating )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Postpone file analysis timeout for %s",
		        info->FileID().c_str());
		info->UpdateLastActivityTime();
		info->ScheduleInactivityTimer();
		return;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "File analysis timeout for %s",
	        info->FileID().c_str());

	RemoveFile(file_id);
	}

bool Manager::RemoveFile(const string& file_id)
	{
	FileMap::iterator it = file_map.find(file_id);

	if ( it == file_map.end() ) return false;

	delete it->second;
	file_map.erase(it);
	return true;
	}
