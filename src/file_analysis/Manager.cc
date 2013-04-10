#include <vector>
#include <string>

#include "Manager.h"
#include "File.h"
#include "Action.h"
#include "Var.h"
#include "Event.h"

using namespace file_analysis;

TableVal* Manager::disabled = 0;

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

void Manager::ReceiveHandle(const string& handle)
	{
	if ( pending.empty() )
		reporter->InternalError("File analysis underflow");

	PendingFile* pf = pending.front();
	if ( ! handle.empty() )
		pf->Finish(handle);
	delete pf;
	pending.pop();
	}

void Manager::EventDrainDone()
	{
	if ( pending.empty() ) return;

	reporter->Error("Too few return_file_handle() calls, discarding pending"
	                " file analysis input.");

	while ( ! pending.empty() )
		{
		delete pending.front();
		pending.pop();
		}
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingDataInChunk(data, len, offset, tag, conn));
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     const string& unique)
	{
	DataIn(data, len, offset, GetFile(unique));
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     File* file)
	{
	if ( ! file ) return;

	file->DataIn(data, len, offset);

	if ( file->IsComplete() )
		RemoveFile(file->GetUnique());
	}

void Manager::DataIn(const u_char* data, uint64 len, AnalyzerTag::Tag tag,
                     Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingDataInStream(data, len, tag, conn));
	}

void Manager::DataIn(const u_char* data, uint64 len, const string& unique)
	{
	DataIn(data, len, GetFile(unique));
	}

void Manager::DataIn(const u_char* data, uint64 len, File* file)
	{
	if ( ! file ) return;

	file->DataIn(data, len);

	if ( file->IsComplete() )
		RemoveFile(file->GetUnique());
	}

void Manager::EndOfFile(AnalyzerTag::Tag tag, Connection* conn)
	{
	EndOfFile(tag, conn, true);
	EndOfFile(tag, conn, false);
	}

void Manager::EndOfFile(AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingEOF(tag, conn));
	}

void Manager::EndOfFile(const string& unique)
	{
	RemoveFile(unique);
	}

void Manager::Gap(uint64 offset, uint64 len, AnalyzerTag::Tag tag,
                  Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingGap(offset, len, tag, conn));
	}

void Manager::Gap(uint64 offset, uint64 len, const string& unique)
	{
	Gap(offset, len, GetFile(unique));
	}

void Manager::Gap(uint64 offset, uint64 len, File* file)
	{
	if ( ! file ) return;

	file->Gap(offset, len);
	}

void Manager::SetSize(uint64 size, AnalyzerTag::Tag tag, Connection* conn,
                      bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingSize(size, tag, conn));
	}

void Manager::SetSize(uint64 size, const string& unique)
	{
	SetSize(size, GetFile(unique));
	}

void Manager::SetSize(uint64 size, File* file)
	{
	if ( ! file ) return;

	file->SetTotalBytes(size);

	if ( file->IsComplete() )
		RemoveFile(file->GetUnique());
	}

void Manager::FileEvent(EventHandlerPtr h, File* file)
	{
	if ( IsIgnored(file->GetUnique()) ) return;
	if ( ! h ) return;

	val_list * vl = new val_list();
	vl->append(file->GetVal()->Ref());
	mgr.Dispatch(new Event(h, vl));
	}

bool Manager::PostponeTimeout(const FileID& file_id) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	file->postpone_timeout = true;
	return true;
	}

bool Manager::AddAction(const FileID& file_id, RecordVal* args) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	return file->AddAction(args);
	}

bool Manager::RemoveAction(const FileID& file_id, const RecordVal* args) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	return file->RemoveAction(args);
	}

File* Manager::GetFile(const string& unique, Connection* conn,
                       AnalyzerTag::Tag tag)
	{
	if ( IsIgnored(unique) ) return 0;

	File* rval = str_map[unique];

	if ( ! rval )
		{
		rval = str_map[unique] = new File(unique, conn, tag);
		FileID id = rval->GetID();

		if ( id_map[id] )
			{
			reporter->Error("Evicted duplicate file ID: %s", id.c_str());
			RemoveFile(unique);
			}

		id_map[id] = rval;
		FileEvent(file_new, rval);
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

File* Manager::Lookup(const FileID& file_id) const
	{
	IDMap::const_iterator it = id_map.find(file_id);

	if ( it == id_map.end() ) return 0;

	return it->second;
	}

void Manager::Timeout(const FileID& file_id, bool is_terminating)
	{
	File* file = Lookup(file_id);

	if ( ! file ) return;

	file->postpone_timeout = false;

	FileEvent(file_timeout, file);

	if ( file->postpone_timeout && ! is_terminating )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Postpone file analysis timeout for %s",
		        file->GetID().c_str());
		file->UpdateLastActivityTime();
		file->ScheduleInactivityTimer();
		return;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "File analysis timeout for %s",
	        file->GetID().c_str());

	RemoveFile(file->GetUnique());
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

	FileID id = it->second->GetID();

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove FileID %s", id.c_str());

	if ( ! id_map.erase(id) )
		reporter->Error("No mapping for fileID %s", id.c_str());

	ignored.erase(unique);
	delete it->second;
	str_map.erase(unique);
	return true;
	}

bool Manager::IsIgnored(const string& unique)
	{
	return ignored.find(unique) != ignored.end();
	}

bool Manager::IsDisabled(AnalyzerTag::Tag tag)
	{
	if ( ! disabled )
		disabled = internal_const_val("FileAnalysis::disable")->AsTableVal();

	Val* index = new Val(tag, TYPE_COUNT);
	Val* yield = disabled->Lookup(index);
	Unref(index);

	if ( ! yield ) return false;

	bool rval = yield->AsBool();
	Unref(yield);

	return rval;
	}

bool Manager::QueueHandleEvent(AnalyzerTag::Tag tag, Connection* conn,
                               bool is_orig)
	{
	if ( ! get_file_handle ) return false;

	val_list* vl = new val_list();
	vl->append(new Val(tag, TYPE_COUNT));
	vl->append(conn->BuildConnVal());
	vl->append(new Val(is_orig, TYPE_BOOL));

	mgr.QueueEvent(get_file_handle, vl);
	return true;
	}
