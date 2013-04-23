#include <vector>
#include <string>

#include "Manager.h"
#include "File.h"
#include "Analyzer.h"
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

void Manager::SetHandle(const string& handle)
	{
	current_handle = handle;
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;

	GetFileHandle(tag, conn, is_orig);
	DataIn(data, len, offset, GetFile(current_handle, conn, tag, is_orig));
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
	GetFileHandle(tag, conn, is_orig);
	// Sequential data input shouldn't be going over multiple conns, so don't
	// do the check to update connection set.
	DataIn(data, len, GetFile(current_handle, conn, tag, is_orig, false));
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

	GetFileHandle(tag, conn, is_orig);
	EndOfFile(current_handle);
	}

void Manager::EndOfFile(const string& unique)
	{
	RemoveFile(unique);
	}

void Manager::Gap(uint64 offset, uint64 len, AnalyzerTag::Tag tag,
                  Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;

	GetFileHandle(tag, conn, is_orig);
	Gap(offset, len, GetFile(current_handle, conn, tag, is_orig));
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

	GetFileHandle(tag, conn, is_orig);
	SetSize(size, GetFile(current_handle, conn, tag, is_orig));
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

bool Manager::PostponeTimeout(const FileID& file_id) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	file->postpone_timeout = true;
	return true;
	}

bool Manager::SetTimeoutInterval(const FileID& file_id, double interval) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	file->SetTimeoutInterval(interval);
	return true;
	}

bool Manager::AddAnalyzer(const FileID& file_id, RecordVal* args) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	return file->AddAnalyzer(args);
	}

bool Manager::RemoveAnalyzer(const FileID& file_id, const RecordVal* args) const
	{
	File* file = Lookup(file_id);

	if ( ! file ) return false;

	return file->RemoveAnalyzer(args);
	}

File* Manager::GetFile(const string& unique, Connection* conn,
                       AnalyzerTag::Tag tag, bool is_orig, bool update_conn)
	{
	if ( unique.empty() ) return 0;
	if ( IsIgnored(unique) ) return 0;

	File* rval = str_map[unique];

	if ( ! rval )
		{
		rval = str_map[unique] = new File(unique, conn, tag, is_orig);
		FileID id = rval->GetID();

		if ( id_map[id] )
			{
			reporter->Error("Evicted duplicate file ID: %s", id.c_str());
			RemoveFile(unique);
			}

		id_map[id] = rval;
		rval->ScheduleInactivityTimer();
		if ( IsIgnored(unique) ) return 0;
		}
	else
		{
		rval->UpdateLastActivityTime();
		if ( update_conn )
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

	file->FileEvent(file_timeout);

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

void Manager::GetFileHandle(AnalyzerTag::Tag tag, Connection* c, bool is_orig)
	{
	current_handle.clear();

	if ( ! get_file_handle ) return;

	val_list* vl = new val_list();
	vl->append(new Val(tag, TYPE_COUNT));
	vl->append(c->BuildConnVal());
	vl->append(new Val(is_orig, TYPE_BOOL));

	mgr.QueueEvent(get_file_handle, vl);
	mgr.Drain(); // need file handle immediately so we don't have to buffer data
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
