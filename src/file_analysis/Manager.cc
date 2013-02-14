#include <vector>
#include <string>

#include "Manager.h"
#include "Info.h"

using namespace file_analysis;

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
