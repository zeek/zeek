// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/AnalyzerSet.h"

#include "zeek/CompHash.h"
#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Manager.h"

namespace zeek::file_analysis::detail {
AnalyzerSet::AnalyzerSet(File* arg_file) : file(arg_file) {}

AnalyzerSet::~AnalyzerSet() {
    while ( ! mod_queue.empty() ) {
        Modification* mod = mod_queue.front();
        mod->Abort();
        delete mod;
        mod_queue.pop();
    }

    for ( const auto& a : analyzer_map )
        delete a.second;

    analyzer_map.clear();
}

Analyzer* AnalyzerSet::Find(const zeek::Tag& tag, RecordValPtr args) {
    auto lv = make_intrusive<ListVal>(TYPE_ANY);
    lv->Append(tag.AsVal());
    lv->Append(std::move(args));

    auto it = analyzer_map.find(lv);
    if ( it != analyzer_map.end() )
        return it->second;

    return nullptr;
}

bool AnalyzerSet::Add(const zeek::Tag& tag, RecordValPtr args) {
    auto lv = make_intrusive<ListVal>(TYPE_ANY);
    lv->Append(tag.AsVal());
    lv->Append(args);

    if ( analyzer_map.contains(lv) ) {
        DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Instantiate analyzer %s skipped: already exists", file->GetID().c_str(),
                file_mgr->GetComponentName(tag).c_str());

        return true;
    }

    file_analysis::Analyzer* a = InstantiateAnalyzer(tag, args);

    if ( ! a )
        return false;

    Insert(a, tag, std::move(args));

    return true;
}

Analyzer* AnalyzerSet::QueueAdd(const zeek::Tag& tag, RecordValPtr args) {
    file_analysis::Analyzer* a = InstantiateAnalyzer(tag, args);

    if ( ! a )
        return nullptr;

    mod_queue.push(new AddMod(a, tag, std::move(args)));

    return a;
}

bool AnalyzerSet::AddMod::Perform(AnalyzerSet* set) {
    auto lv = make_intrusive<ListVal>(TYPE_ANY);
    lv->Append(tag.AsVal());
    lv->Append(args);

    if ( set->analyzer_map.contains(lv) ) {
        DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Add analyzer %s skipped: already exists", a->GetFile()->GetID().c_str(),
                file_mgr->GetComponentName(a->Tag()).c_str());

        Abort();
        return true;
    }

    set->Insert(a, tag, args);

    return true;
}

void AnalyzerSet::AddMod::Abort() {
    delete a;
    a = nullptr;
}

bool AnalyzerSet::Remove(const zeek::Tag& tag, RecordValPtr args) {
    auto lv = make_intrusive<ListVal>(TYPE_ANY);
    lv->Append(tag.AsVal());
    lv->Append(std::move(args));

    auto a = analyzer_map.find(lv);

    if ( a == analyzer_map.end() ) {
        DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Skip remove analyzer %s", file->GetID().c_str(),
                file_mgr->GetComponentName(tag).c_str());
        return false;
    }

    DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Remove analyzer %s", file->GetID().c_str(),
            file_mgr->GetComponentName(tag).c_str());

    a->second->Done();

    // We don't delete the analyzer object right here because the remove
    // operation may execute at a time when it can still be accessed.
    // Instead we let the file know to delete the analyzer later.
    file->DoneWithAnalyzer(a->second);

    analyzer_map.erase(a);

    return true;
}

bool AnalyzerSet::QueueRemove(const zeek::Tag& tag, RecordValPtr args) {
    auto lv = make_intrusive<ListVal>(TYPE_ANY);
    lv->Append(tag.AsVal());
    lv->Append(args);

    auto it = analyzer_map.find(lv);

    mod_queue.push(new RemoveMod(tag, std::move(args)));
    return it != analyzer_map.end();
}

bool AnalyzerSet::RemoveMod::Perform(AnalyzerSet* set) { return set->Remove(tag, args); }

file_analysis::Analyzer* AnalyzerSet::InstantiateAnalyzer(const Tag& tag, RecordValPtr args) const {
    auto a = file_mgr->InstantiateAnalyzer(tag, std::move(args), file);

    if ( ! a ) {
        auto c = file_mgr->Lookup(tag);

        if ( c && ! c->Enabled() )
            return nullptr;

        reporter->Error("[%s] Failed file analyzer %s instantiation", file->GetID().c_str(),
                        file_mgr->GetComponentName(tag).c_str());
        return nullptr;
    }

    return a;
}

void AnalyzerSet::Insert(file_analysis::Analyzer* a, const Tag& tag, RecordValPtr args) {
    DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Add analyzer %s", file->GetID().c_str(),
            file_mgr->GetComponentName(a->Tag()).c_str());

    auto lv = make_intrusive<ListVal>(TYPE_ANY);
    lv->Append(tag.AsVal());
    lv->Append(std::move(args));

    analyzer_map.insert({lv, a});

    a->Init();
}

void AnalyzerSet::DrainModifications() {
    if ( mod_queue.empty() )
        return;

    DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Start analyzer mod queue flush", file->GetID().c_str());
    do {
        Modification* mod = mod_queue.front();
        mod->Perform(this);
        delete mod;
        mod_queue.pop();
    } while ( ! mod_queue.empty() );
    DBG_LOG(DBG_FILE_ANALYSIS, "[%s] End flushing analyzer mod queue.", file->GetID().c_str());
}

} // namespace zeek::file_analysis::detail
