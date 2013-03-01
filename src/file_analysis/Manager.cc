#include <vector>
#include <string>

#include "Manager.h"
#include "Info.h"
#include "Action.h"

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

void Manager::DataIn(const string& unique, const u_char* data, uint64 len,
                     uint64 offset, Connection* conn, const string& protocol)
	{
	if ( IsIgnored(unique) ) return;

	Info* info = GetInfo(unique, conn, protocol);

	if ( ! info ) return;

	info->DataIn(data, len, offset);

	if ( info->IsComplete() )
		RemoveFile(unique);
	}

void Manager::DataIn(const string& unique, const u_char* data, uint64 len,
                     Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);

	if ( ! info ) return;

	info->DataIn(data, len);

	if ( info->IsComplete() )
		RemoveFile(unique);
	}

void Manager::EndOfFile(const string& unique, Connection* conn,
                        const string& protocol)
	{
	// Just call GetInfo because maybe the conn/protocol args will update
	// something in the Info record.
	GetInfo(unique, conn, protocol);
	RemoveFile(unique);
	}

void Manager::Gap(const string& unique, uint64 offset, uint64 len,
                  Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);

	if ( ! info ) return;

	info->Gap(offset, len);
	}

void Manager::SetSize(const string& unique, uint64 size,
                      Connection* conn, const string& protocol)
	{
	Info* info = GetInfo(unique, conn, protocol);

	if ( ! info ) return;

	info->SetTotalBytes(size);

	if ( info->IsComplete() )
		RemoveFile(unique);
	}

void Manager::EvaluatePolicy(BifEnum::FileAnalysis::Trigger t, Info* info)
	{
	if ( IsIgnored(info->GetUnique()) ) return;

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

bool Manager::AddAction(const FileID& file_id, RecordVal* args) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->AddAction(args);
	}

bool Manager::RemoveAction(const FileID& file_id, const RecordVal* args) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->RemoveAction(args);
	}

Info* Manager::GetInfo(const string& unique, Connection* conn,
                       const string& protocol)
	{
	if ( IsIgnored(unique) ) return 0;

	Info* rval = str_map[unique];

	if ( ! rval )
		{
		rval = str_map[unique] = new Info(unique, conn, protocol);
		FileID id = rval->GetFileID();

		if ( id_map[id] )
			{
			reporter->Error("Evicted duplicate file ID: %s", id.c_str());
			RemoveFile(unique);
			}

		id_map[id] = rval;
		file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_NEW, rval);
		rval->ScheduleInactivityTimer();
		if ( IsIgnored(unique) ) return 0;
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

	file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TIMEOUT, info);

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

	RemoveFile(info->GetUnique());
	}

bool Manager::IgnoreFile(const FileID& file_id)
	{
	IDMap::iterator it = id_map.find(file_id);

	if ( it == id_map.end() ) return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Ignore FileID %s", file_id.c_str());

	ignored.insert(it->second->GetUnique());

	return true;
	}

bool Manager::RemoveFile(const string& unique)
	{
	StrMap::iterator it = str_map.find(unique);

	if ( it == str_map.end() ) return false;

	it->second->EndOfFile();

	FileID id = it->second->GetFileID();

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove FileID %s", id.c_str());

	if ( ! id_map.erase(id) )
		reporter->Error("No mapping for fileID %s", id.c_str());

	ignored.erase(unique);
	str_map.erase(unique);
	delete it->second;
	return true;
	}

bool Manager::IsIgnored(const string& unique)
	{
	return ignored.find(unique) != ignored.end();
	}
