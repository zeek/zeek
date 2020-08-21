// See the file "COPYING" in the main distribution directory for copyright.

#include "AnalyzerSet.h"
#include "File.h"
#include "Analyzer.h"
#include "Manager.h"
#include "CompHash.h"
#include "Val.h"
#include "file_analysis/file_analysis.bif.h"

namespace zeek::file_analysis::detail {

static void analyzer_del_func(void* v)
	{
	file_analysis::Analyzer* a = (file_analysis::Analyzer*)v;

	a->Done();
	delete a;
	}

AnalyzerSet::AnalyzerSet(File* arg_file) : file(arg_file)
	{
	auto t = zeek::make_intrusive<zeek::TypeList>();
	t->Append(file_mgr->GetTagType());
	t->Append(zeek::BifType::Record::Files::AnalyzerArgs);
	analyzer_hash = new zeek::detail::CompositeHash(std::move(t));
	analyzer_map.SetDeleteFunc(analyzer_del_func);
	}

AnalyzerSet::~AnalyzerSet()
	{
	while ( ! mod_queue.empty() )
		{
		Modification* mod = mod_queue.front();
		mod->Abort();
		delete mod;
		mod_queue.pop();
		}

	delete analyzer_hash;
	}

Analyzer* AnalyzerSet::Find(const file_analysis::Tag& tag,
                            zeek::RecordValPtr args)
	{
	auto key = GetKey(tag, std::move(args));
	Analyzer* rval = analyzer_map.Lookup(key.get());
	return rval;
	}

bool AnalyzerSet::Add(const file_analysis::Tag& tag, zeek::RecordValPtr args)
	{
	auto key = GetKey(tag, args);

	if ( analyzer_map.Lookup(key.get()) )
		{
		DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] Instantiate analyzer %s skipped: already exists",
		        file->GetID().c_str(),
		        file_mgr->GetComponentName(tag).c_str());

		return true;
		}

	file_analysis::Analyzer* a = InstantiateAnalyzer(tag, std::move(args));

	if ( ! a )
		return false;

	Insert(a, std::move(key));

	return true;
	}

Analyzer* AnalyzerSet::QueueAdd(const file_analysis::Tag& tag,
                                zeek::RecordValPtr args)
	{
	auto key = GetKey(tag, args);
	file_analysis::Analyzer* a = InstantiateAnalyzer(tag, std::move(args));

	if ( ! a )
		return nullptr;

	mod_queue.push(new AddMod(a, std::move(key)));

	return a;
	}

bool AnalyzerSet::AddMod::Perform(AnalyzerSet* set)
	{
	if ( set->analyzer_map.Lookup(key.get()) )
		{
		DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] Add analyzer %s skipped: already exists",
		        a->GetFile()->GetID().c_str(),
		        file_mgr->GetComponentName(a->Tag()).c_str());

		Abort();
		return true;
		}

	set->Insert(a, std::move(key));

	return true;
	}

void AnalyzerSet::AddMod::Abort()
	{
	delete a;
	}

bool AnalyzerSet::Remove(const file_analysis::Tag& tag,
                         zeek::RecordValPtr args)
	{
	return Remove(tag, GetKey(tag, std::move(args)));
	}

bool AnalyzerSet::Remove(const file_analysis::Tag& tag,
                         std::unique_ptr<zeek::detail::HashKey> key)
	{
	auto a = (file_analysis::Analyzer*) analyzer_map.Remove(key.get());

	if ( ! a )
		{
		DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] Skip remove analyzer %s",
		        file->GetID().c_str(), file_mgr->GetComponentName(tag).c_str());
		return false;
		}

	DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] Remove analyzer %s",
	        file->GetID().c_str(),
	        file_mgr->GetComponentName(tag).c_str());

	a->Done();

	// We don't delete the analyzer object right here because the remove
	// operation may execute at a time when it can still be accessed.
	// Instead we let the file know to delete the analyzer later.
	file->DoneWithAnalyzer(a);

	return true;
	}

bool AnalyzerSet::QueueRemove(const file_analysis::Tag& tag,
                              zeek::RecordValPtr args)
	{
	auto key = GetKey(tag, std::move(args));
	auto rval = analyzer_map.Lookup(key.get());
	mod_queue.push(new RemoveMod(tag, std::move(key)));
	return rval;
	}

bool AnalyzerSet::RemoveMod::Perform(AnalyzerSet* set)
	{
	return set->Remove(tag, std::move(key));
	}

std::unique_ptr<zeek::detail::HashKey> AnalyzerSet::GetKey(const file_analysis::Tag& t,
                                                           zeek::RecordValPtr args) const
	{
	auto lv = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
	lv->Append(t.AsVal());
	lv->Append(std::move(args));
	auto key = analyzer_hash->MakeHashKey(*lv, true);

	if ( ! key )
		zeek::reporter->InternalError("AnalyzerArgs type mismatch");

	return key;
	}

file_analysis::Analyzer* AnalyzerSet::InstantiateAnalyzer(const Tag& tag,
                                                          zeek::RecordValPtr args) const
	{
	auto  a = file_mgr->InstantiateAnalyzer(tag, std::move(args), file);

	if ( ! a )
		{
		zeek::reporter->Error("[%s] Failed file analyzer %s instantiation",
		                      file->GetID().c_str(),
		                      file_mgr->GetComponentName(tag).c_str());
		return nullptr;
		}

	return a;
	}

void AnalyzerSet::Insert(file_analysis::Analyzer* a,
                         std::unique_ptr<zeek::detail::HashKey> key)
	{
	DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] Add analyzer %s",
	        file->GetID().c_str(), file_mgr->GetComponentName(a->Tag()).c_str());
	analyzer_map.Insert(key.get(), a);

	a->Init();
	}

void AnalyzerSet::DrainModifications()
	{
	if ( mod_queue.empty() )
		return;

	DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] Start analyzer mod queue flush",
	        file->GetID().c_str());
	do
		{
		Modification* mod = mod_queue.front();
		mod->Perform(this);
		delete mod;
		mod_queue.pop();
		} while ( ! mod_queue.empty() );
	DBG_LOG(zeek::DBG_FILE_ANALYSIS, "[%s] End flushing analyzer mod queue.",
	        file->GetID().c_str());
	}

} // namespace zeek::file_analysis::detail
