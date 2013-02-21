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
	vector<FileID> keys;
	for ( IDMap::iterator it = id_map.begin(); it != id_map.end(); ++it )
		keys.push_back(it->first);
	for ( size_t i = 0; i < keys.size(); ++i )
		Timeout(keys[i], true);
	}

static void check_file_done(Info* info)
	{
	if ( info->IsComplete() )
		{
		Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_DONE, info);
		file_mgr->RemoveFile(info->GetFileID());
		}
	}

void Manager::DataIn(const string& unique, const u_char* data, uint64 len,
                     uint64 offset, Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);
	info->DataIn(data, len, offset);
	check_file_done(info);
	}

void Manager::DataIn(const string& unique, const u_char* data, uint64 len,
                     Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);
	info->DataIn(data, len);
	check_file_done(info);
	}

void Manager::EndOfFile(const string& unique, Connection* conn,
                        const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);
	info->EndOfFile();
	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_EOF, info);
	}

void Manager::Gap(const string& unique, uint64 offset, uint64 len,
                  Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);
	info->Gap(offset, len);
	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_GAP, info);
	}

void Manager::SetSize(const string& unique, uint64 size,
                      Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);
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

bool Manager::PostponeTimeout(const FileID& file_id) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	info->postpone_timeout = true;
	return true;
	}

bool Manager::AddAction(const FileID& file_id, EnumVal* act,
                        RecordVal* args) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->AddAction(act, args);
	}

bool Manager::RemoveAction(const FileID& file_id, EnumVal* act) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->RemoveAction(act);
	}

Info* Manager::GetInfo(const string& unique, Connection* conn,
                       const string& protocol)
	{
	Info* rval = str_map[unique];

	if ( ! rval )
		{
		rval = str_map[unique] = new Info(unique, conn, protocol);
		FileID id = rval->GetFileID();

		if ( id_map[id] )
			{
			reporter->Error("Evicted duplicate file ID: %s", id.c_str());
			RemoveFile(id);
			}

		id_map[id] = rval;
		Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_NEW, rval);
		}
	else
		{
		rval->UpdateLastActivityTime();
		rval->UpdateConnectionFields(conn);
		}

	return rval;
	}

Info* Manager::Lookup(const FileID& file_id) const
	{
	IDMap::const_iterator it = id_map.find(file_id);

	if ( it == id_map.end() ) return 0;

	return it->second;
	}

void Manager::Timeout(const FileID& file_id, bool is_terminating)
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return;

	Manager::EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TIMEOUT, info);

	if ( info->postpone_timeout && ! is_terminating )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Postpone file analysis timeout for %s",
		        info->GetFileID().c_str());
		info->UpdateLastActivityTime();
		info->ScheduleInactivityTimer();
		return;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "File analysis timeout for %s",
	        info->GetFileID().c_str());

	RemoveFile(file_id);
	}

bool Manager::RemoveFile(const FileID& file_id)
	{
	IDMap::iterator it = id_map.find(file_id);

	if ( it == id_map.end() ) return false;

	if ( ! str_map.erase(it->second->Unique()) )
		reporter->Error("No string mapping for file ID %s", file_id.c_str());
	delete it->second;
	id_map.erase(it);
	return true;
	}
