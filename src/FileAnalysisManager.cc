#include <vector>

#include "FileAnalysisManager.h"
#include "util.h"

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
int Info::undelivered_idx = -1;
int Info::timeout_interval_idx = -1;

Info::Info(const string& file_id, Connection* conn, AnalyzerTag::Tag at)
    : val(0), last_activity_time(network_time), postpone_timeout(false)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Creating new Info object %s", file_id.c_str());

	if ( file_id_idx == -1 )
		{
		file_id_idx = Idx("file_id");
		parent_file_id_idx = Idx("parent_file_id");
		protocol_idx = Idx("protocol");
		conn_uids_idx = Idx("conn_uids");
		conn_ids_idx = Idx("conn_ids");
		seen_bytes_idx = Idx("seen_bytes");
		total_bytes_idx = Idx("total_bytes");
		undelivered_idx = Idx("undelivered");
		timeout_interval_idx = Idx("timeout_interval");
		}

	val = new RecordVal(BifType::Record::FileAnalysis::Info);
	val->Assign(file_id_idx, new StringVal(file_id.c_str()));

	UpdateConnectionFields(conn);

	if ( at != AnalyzerTag::Error )
		val->Assign(protocol_idx, new StringVal(Analyzer::GetTagName(at)));

	ScheduleInactivityTimer();
	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_NEW, this);
	}

Info::~Info()
	{
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
	return val->LookupWithDefault(timeout_interval_idx)->AsInterval();
	}

string Info::FileID() const
	{
	return val->Lookup(file_id_idx)->AsString()->CheckString();
	}

void Info::SetTotalBytes(uint64 size)
	{
	val->Assign(total_bytes_idx, new Val(size, TYPE_COUNT));

	if ( val->LookupWithDefault(seen_bytes_idx)->AsCount() >= size )
		{
		Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_DONE, this);
		file_mgr->Remove(FileID());
		}
	}

void Info::ScheduleInactivityTimer() const
	{
	timer_mgr->Add(new InfoTimer(network_time, FileID(), TimeoutInterval()));
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

void Manager::DataIn(const string& file_id, const u_char* data, uint64 len,
                     uint64 offset, Connection* conn, AnalyzerTag::Tag at)
	{
	Info* info = IDtoInfo(file_id, conn, at);
	info->UpdateLastActivityTime();
	info->UpdateConnectionFields(conn);
	// TODO: more stuff
	}

void Manager::DataIn(const string& file_id, const u_char* data, uint64 len,
                     Connection* conn, AnalyzerTag::Tag at)
	{
	Info* info = IDtoInfo(file_id, conn, at);
	info->UpdateLastActivityTime();
	info->UpdateConnectionFields(conn);
	// TODO: more stuff
	}

void Manager::SetSize(const string& file_id, uint64 size,
                      Connection* conn, AnalyzerTag::Tag at)
	{
	Info* info = IDtoInfo(file_id, conn, at);
	info->UpdateLastActivityTime();
	info->UpdateConnectionFields(conn);
	info->SetTotalBytes(size);
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

Info* Manager::IDtoInfo(const string& file_id, Connection* conn,
                        AnalyzerTag::Tag at)
	{
	Info* rval = file_map[file_id];
	if ( ! rval )
		rval = file_map[file_id] = new Info(file_id, conn, at);
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

	EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TIMEOUT, info);

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

	file_map.erase(file_id);
	delete info;
	}

void Manager::Remove(const string& file_id)
	{
	FileMap::iterator it = file_map.find(file_id);

	if ( it == file_map.end() ) return;

	delete it->second;
	file_map.erase(it);
	}
