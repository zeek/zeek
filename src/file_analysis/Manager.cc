// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/Manager.h"

#include <openssl/md5.h>

#include "zeek/Event.h"
#include "zeek/UID.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/digest.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/file_analysis.bif.h"
#include "zeek/plugin/Manager.h"

using namespace std;

namespace zeek::file_analysis
	{

Manager::Manager()
	: plugin::ComponentManager<file_analysis::Component>("Files", "Tag", "AllAnalyzers"),
	  current_file_id(), magic_state(), cumulative_files(0), max_files(0)
	{
	}

Manager::~Manager()
	{
	for ( MIMEMap::iterator i = mime_types.begin(); i != mime_types.end(); i++ )
		delete i->second;

	// Have to assume that too much of Zeek has been shutdown by this point
	// to do anything more than reclaim memory.
	for ( const auto& entry : id_map )
		delete entry.second;

	delete magic_state;
	}

void Manager::InitPreScript() { }

void Manager::InitPostScript() { }

void Manager::InitMagic()
	{
	delete magic_state;
	magic_state = zeek::detail::rule_matcher->InitFileMagic();
	}

void Manager::Terminate()
	{
	vector<string> keys;
	keys.reserve(id_map.size());

	for ( const auto& entry : id_map )
		keys.push_back(entry.first);

	for ( const string& key : keys )
		Timeout(key, true);

	event_mgr.Drain();
	}

string Manager::HashHandle(const string& handle) const
	{
	zeek::detail::hash128_t hash;
	zeek::detail::KeyedHash::StaticHash128(handle.data(), handle.size(), &hash);

	return UID(zeek::detail::bits_per_uid, hash, 2).Base62("F");
	}

void Manager::SetHandle(const string& handle)
	{
	if ( handle.empty() )
		return;

#ifdef DEBUG
	if ( zeek::detail::debug_logger.IsEnabled(DBG_FILE_ANALYSIS) )
		{
		String tmp{handle};
		auto rendered = tmp.Render();
		DBG_LOG(DBG_FILE_ANALYSIS, "Set current handle to %s", rendered);
		delete[] rendered;
		}
#endif

	current_file_id = HashHandle(handle);
	}

string Manager::DataIn(const u_char* data, uint64_t len, uint64_t offset, const zeek::Tag& tag,
                       Connection* conn, bool is_orig, const string& precomputed_id,
                       const string& mime_type)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	File* file = GetFile(id, conn, tag, is_orig);

	if ( ! file )
		return "";

	// This only has any effect when
	// * called for the first time for a file
	// * being called before file->DataIn is called for the first time (before data is
	//   added to the bof buffer).
	// Afterwards SetMime just ignores what is passed to it. Thus this only has effect during
	// the first Manager::DataIn call for each file.
	if ( ! mime_type.empty() )
		file->SetMime(mime_type);

	file->DataIn(data, len, offset);

	if ( file->IsComplete() )
		{
		RemoveFile(file->GetID());
		return "";
		}

	return id;
	}

string Manager::DataIn(const u_char* data, uint64_t len, const zeek::Tag& tag, Connection* conn,
                       bool is_orig, const string& precomputed_id, const string& mime_type)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	// Sequential data input shouldn't be going over multiple conns, so don't
	// do the check to update connection set.
	File* file = GetFile(id, conn, tag, is_orig, false);

	if ( ! file )
		return "";

	if ( ! mime_type.empty() )
		file->SetMime(mime_type);

	file->DataIn(data, len);

	if ( file->IsComplete() )
		{
		RemoveFile(file->GetID());
		return "";
		}

	return id;
	}

void Manager::DataIn(const u_char* data, uint64_t len, const string& file_id, const string& source,
                     const string& mime_type)
	{
	File* file = GetFile(file_id, nullptr, zeek::Tag::Error, false, false, source.c_str());

	if ( ! file )
		return;

	if ( ! mime_type.empty() )
		file->SetMime(mime_type);

	file->DataIn(data, len);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

void Manager::DataIn(const u_char* data, uint64_t len, uint64_t offset, const string& file_id,
                     const string& source, const string& mime_type)
	{
	File* file = GetFile(file_id, nullptr, zeek::Tag::Error, false, false, source.c_str());

	if ( ! file )
		return;

	if ( ! mime_type.empty() )
		file->SetMime(mime_type);

	file->DataIn(data, len, offset);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

void Manager::EndOfFile(const zeek::Tag& tag, Connection* conn)
	{
	EndOfFile(tag, conn, true);
	EndOfFile(tag, conn, false);
	}

void Manager::EndOfFile(const zeek::Tag& tag, Connection* conn, bool is_orig)
	{
	// Don't need to create a file if we're just going to remove it right away.
	RemoveFile(GetFileID(tag, conn, is_orig));
	}

void Manager::EndOfFile(const string& file_id)
	{
	RemoveFile(file_id);
	}

string Manager::Gap(uint64_t offset, uint64_t len, const zeek::Tag& tag, Connection* conn,
                    bool is_orig, const string& precomputed_id)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	File* file = GetFile(id, conn, tag, is_orig);

	if ( ! file )
		return "";

	file->Gap(offset, len);
	return id;
	}

string Manager::SetSize(uint64_t size, const zeek::Tag& tag, Connection* conn, bool is_orig,
                        const string& precomputed_id)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	File* file = GetFile(id, conn, tag, is_orig);

	if ( ! file )
		return "";

	file->SetTotalBytes(size);

	if ( file->IsComplete() )
		{
		RemoveFile(file->GetID());
		return "";
		}

	return id;
	}

bool Manager::SetTimeoutInterval(const string& file_id, double interval) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	if ( interval > 0 )
		file->postpone_timeout = true;

	file->SetTimeoutInterval(interval);
	return true;
	}

bool Manager::EnableReassembly(const string& file_id)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	file->EnableReassembly();
	return true;
	}

bool Manager::DisableReassembly(const string& file_id)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	file->DisableReassembly();
	return true;
	}

bool Manager::SetReassemblyBuffer(const string& file_id, uint64_t max)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	file->SetReassemblyBuffer(max);
	return true;
	}

bool Manager::SetExtractionLimit(const string& file_id, RecordValPtr args, uint64_t n) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	return file->SetExtractionLimit(std::move(args), n);
	}

bool Manager::AddAnalyzer(const string& file_id, const zeek::Tag& tag, RecordValPtr args) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	return file->AddAnalyzer(tag, std::move(args));
	}

bool Manager::RemoveAnalyzer(const string& file_id, const zeek::Tag& tag, RecordValPtr args) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	return file->RemoveAnalyzer(tag, std::move(args));
	}

File* Manager::GetFile(const string& file_id, Connection* conn, const zeek::Tag& tag, bool is_orig,
                       bool update_conn, const char* source_name)
	{
	if ( file_id.empty() )
		return nullptr;

	if ( IsIgnored(file_id) )
		return nullptr;

	File* rval = LookupFile(file_id);

	if ( ! rval )
		{
		rval = new File(file_id, source_name ? source_name : analyzer_mgr->GetComponentName(tag),
		                conn, tag, is_orig);
		id_map[file_id] = rval;

		++cumulative_files;
		if ( id_map.size() > max_files )
			max_files = id_map.size();

		rval->ScheduleInactivityTimer();

		// Generate file_new after inserting it into manager's mapping
		// in case script-layer calls back into core from the event.
		rval->FileEvent(file_new);
		// Same for file_over_new_connection.
		rval->RaiseFileOverNewConnection(conn, is_orig);

		if ( IsIgnored(file_id) )
			return nullptr;
		}
	else
		{
		rval->UpdateLastActivityTime();

		if ( update_conn && rval->UpdateConnectionFields(conn, is_orig) )
			rval->RaiseFileOverNewConnection(conn, is_orig);
		}

	return rval;
	}

File* Manager::LookupFile(const string& file_id) const
	{
	const auto& entry = id_map.find(file_id);
	if ( entry == id_map.end() )
		return nullptr;

	return entry->second;
	}

void Manager::Timeout(const string& file_id, bool is_terminating)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return;

	file->postpone_timeout = false;

	file->FileEvent(file_timeout);

	if ( file->postpone_timeout && ! is_terminating )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Postpone file analysis timeout for %s", file->GetID().c_str());
		file->UpdateLastActivityTime();
		file->ScheduleInactivityTimer();
		return;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "File analysis timeout for %s", file->GetID().c_str());

	RemoveFile(file->GetID());
	}

bool Manager::IgnoreFile(const string& file_id)
	{
	if ( ! LookupFile(file_id) )
		return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Ignore FileID %s", file_id.c_str());

	ignored.insert(file_id);
	return true;
	}

bool Manager::RemoveFile(const string& file_id)
	{
	// Can't remove from the dictionary/map right away as invoking EndOfFile
	// may cause some events to be executed which actually depend on the file
	// still being in the dictionary/map.
	File* f = LookupFile(file_id);

	if ( ! f )
		return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Remove file", file_id.c_str());

	f->EndOfFile();

	id_map.erase(file_id);
	ignored.erase(file_id);
	delete f;
	return true;
	}

bool Manager::IsIgnored(const string& file_id)
	{
	return ignored.find(file_id) != ignored.end();
	}

string Manager::GetFileID(const zeek::Tag& tag, Connection* c, bool is_orig)
	{
	current_file_id.clear();

	if ( IsDisabled(tag) )
		return "";

	if ( ! get_file_handle )
		return "";

	DBG_LOG(DBG_FILE_ANALYSIS, "Raise get_file_handle() for protocol analyzer %s",
	        analyzer_mgr->GetComponentName(tag).c_str());

	const auto& tagval = tag.AsVal();

	event_mgr.Enqueue(get_file_handle, tagval, c->GetVal(), val_mgr->Bool(is_orig));
	event_mgr.Drain(); // need file handle immediately so we don't have to buffer data
	return current_file_id;
	}

bool Manager::IsDisabled(const zeek::Tag& tag)
	{
	if ( ! disabled )
		disabled = id::find_const("Files::disable")->AsTableVal();

	auto index = val_mgr->Count(bool(tag));
	auto yield = disabled->FindOrDefault(index);

	if ( ! yield )
		return false;

	return yield->AsBool();
	}

Analyzer* Manager::InstantiateAnalyzer(const Tag& tag, RecordValPtr args, File* f) const
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning("unknown file analyzer instantiation request: %s",
		                          tag.AsString().c_str());
		return nullptr;
		}

	if ( ! c->Enabled() )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Skip instantiation of disabled analyzer %s", f->id.c_str(),
		        GetComponentName(tag).c_str());
		return nullptr;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Instantiate analyzer %s", f->id.c_str(),
	        GetComponentName(tag).c_str());

	Analyzer* a;

	if ( c->factory_func )
		a = c->factory_func(std::move(args), f);
	else
		{
		reporter->InternalWarning("file analyzer %s cannot be instantiated "
		                          "dynamically",
		                          c->CanonicalName().c_str());
		return nullptr;
		}

	if ( ! a )
		reporter->InternalError("file analyzer instantiation failed");

	a->SetAnalyzerTag(tag);

	return a;
	}

zeek::detail::RuleMatcher::MIME_Matches*
Manager::DetectMIME(const u_char* data, uint64_t len,
                    zeek::detail::RuleMatcher::MIME_Matches* rval) const
	{
	if ( ! magic_state )
		reporter->InternalError("file magic signature state not initialized");

	rval = zeek::detail::rule_matcher->Match(magic_state, data, len, rval);
	zeek::detail::rule_matcher->ClearFileMagicState(magic_state);
	return rval;
	}

string Manager::DetectMIME(const u_char* data, uint64_t len) const
	{
	zeek::detail::RuleMatcher::MIME_Matches matches;
	DetectMIME(data, len, &matches);

	if ( matches.empty() )
		return "";

	return *(matches.begin()->second.begin());
	}

VectorValPtr GenMIMEMatchesVal(const zeek::detail::RuleMatcher::MIME_Matches& m)
	{
	static auto mime_matches = id::find_type<VectorType>("mime_matches");
	static auto mime_match = id::find_type<RecordType>("mime_match");
	auto rval = make_intrusive<VectorVal>(mime_matches);

	for ( zeek::detail::RuleMatcher::MIME_Matches::const_iterator it = m.begin(); it != m.end();
	      ++it )
		{
		auto element = make_intrusive<RecordVal>(mime_match);

		for ( set<string>::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2 )
			{
			element->Assign(0, it->first);
			element->Assign(1, *it2);
			}

		rval->Assign(rval->Size(), std::move(element));
		}

	return rval;
	}

	} // namespace zeek::file_analysis
