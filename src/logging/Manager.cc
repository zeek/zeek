// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/logging/Manager.h"

#include <broker/endpoint_info.hh>
#include <functional>
#include <optional>
#include <utility>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/File.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/NetVar.h"
#include "zeek/OpaqueVal.h"
#include "zeek/RunState.h"
#include "zeek/Type.h"
#include "zeek/broker/Manager.h"
#include "zeek/input.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/logging/WriterFrontend.h"
#include "zeek/logging/logging.bif.h"
#include "zeek/plugin/Manager.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/threading/Manager.h"
#include "zeek/threading/SerialTypes.h"

using namespace std;

namespace zeek::detail {

extern zeek::OpaqueTypePtr log_delay_token_type;

};

namespace zeek::logging {

namespace detail {
using DelayTokenType = zeek_uint_t;

class DelayInfo;

using DelayInfoPtr = std::shared_ptr<DelayInfo>;

class LogDelayTokenVal : public OpaqueVal {
public:
    explicit LogDelayTokenVal(DelayTokenType token) : OpaqueVal(zeek::detail::log_delay_token_type), token(token) {}
    virtual ~LogDelayTokenVal() = default;

    ValPtr DoClone(CloneState* state) override;

    DelayTokenType Token() { return token; }

protected:
    explicit LogDelayTokenVal() : LogDelayTokenVal(0) {}
    DECLARE_OPAQUE_VALUE_DATA(LogDelayTokenVal)

private:
    DelayTokenType token;
};

ValPtr LogDelayTokenVal::DoClone(CloneState* state) {
    return state->NewClone(this, make_intrusive<LogDelayTokenVal>(Token()));
}

// Delay tokens are only valid on the same worker.
std::optional<BrokerData> LogDelayTokenVal::DoSerializeData() const { return std::nullopt; }

bool LogDelayTokenVal::DoUnserializeData(BrokerDataView) { return false; }

IMPLEMENT_OPAQUE_VALUE(LogDelayTokenVal)

DelayTokenType to_internal_delay_token(const ValPtr& val) {
    assert(val->GetType()->Tag() == TYPE_OPAQUE);
    if ( auto* optr = dynamic_cast<LogDelayTokenVal*>(val.get()) )
        return optr->Token();

    zeek::reporter->Error("dynamic_cast of LogDelayToken failed: wrong opaque type provided?");
    return 0;
}

using DelayWriteMap = std::map<WriteContext, DelayInfoPtr>;
using DelayTokenMap = std::unordered_map<DelayTokenType, DelayInfoPtr>;
using DelayQueue = std::list<DelayInfoPtr>;

// DelayInfo tracks information of Log::write() operation that was
// delayed during execution of the Log::log_stream_policy hook.
class DelayInfo {
public:
    static const DelayInfoPtr nil;

    explicit DelayInfo(const WriteContext& ctx, const zeek::ValPtr token_val, double expire_time)
        : ctx(ctx), token_val(token_val), expire_time(expire_time) {}

    // No copy or assignment of DelayInfo itself, should
    // always be managed through a shared pointer.
    DelayInfo(const DelayInfo&) = delete;
    DelayInfo& operator=(const DelayInfo&) = delete;

    void IncDelayRefs() { ++delay_refs; };
    void DecDelayRefs() {
        assert(delay_refs > 0);
        --delay_refs;
    };
    int DelayRefs() const { return delay_refs; };
    bool HasDelayRefs() const { return delay_refs > 0; };

    const RecordValPtr& Record() const { return ctx.record; }
    const EnumValPtr& StreamId() const { return ctx.id; }
    const WriteContext& Context() const { return ctx; }

    const ValPtr& TokenVal() const { return token_val; }
    double ExpireTime() const { return expire_time; }

    // The position in the delay queue for efficient removal.
    DelayQueue::const_iterator QueuePosition() const { return queue_position; }
    bool IsInQueue() const { return enqueued; }
    void SetQueuePosition(DelayQueue::const_iterator pos) {
        queue_position = pos;
        enqueued = true;
    }

    const std::vector<FuncPtr>& PostDelayCallbacks() const { return post_delay_callbacks; }
    void AppendPostDelayCallback(FuncPtr f) { post_delay_callbacks.emplace_back(std::move(f)); }

private:
    // Active log write information
    WriteContext ctx;

    // References - number of Log::delay() calls.
    int delay_refs = 1;

    // Token for this delay.
    ValPtr token_val;

    // Stamped on the first Log::delay() call during
    // Log::log_stream_policy execution.
    double expire_time = 0.0;

    // Callbacks to invoke when all references were released, or the delay expired.
    std::vector<FuncPtr> post_delay_callbacks;

    // Has this DelayInfo object been enqueued?
    bool enqueued = false;

    // Iterator pointing at this instance in the delay_queue.
    DelayQueue::const_iterator queue_position;
};

const DelayInfoPtr DelayInfo::nil = nullptr;

// Timer for the head of the per stream delay queue using an opaque
// callback based approach to hide the Stream implementation details.
class LogDelayExpiredTimer : public zeek::detail::Timer {
public:
    LogDelayExpiredTimer(std::function<void(double, bool)> dispatch_callback, double t)
        : Timer(t, zeek::detail::TIMER_LOG_DELAY_EXPIRE), dispatch_callback(std::move(dispatch_callback)) {}

    void Dispatch(double t, bool is_expire) override { dispatch_callback(t, is_expire); }

private:
    std::function<void(double, bool)> dispatch_callback;
};

// Helper class for dealing with nested Write() calls.
class ActiveWriteScope {
public:
    ActiveWriteScope(std::vector<WriteContext>& active_writes, WriteContext w) : active_writes{active_writes} {
        active_writes.push_back(std::move(w));
    }
    ~ActiveWriteScope() { active_writes.pop_back(); }

private:
    std::vector<WriteContext>& active_writes;
};

} // namespace detail


struct Manager::Filter {
    Val* fval = nullptr;
    string name;
    EnumVal* id = nullptr;
    Func* policy = nullptr;
    Func* path_func = nullptr;
    string path;
    Val* path_val = nullptr;
    EnumVal* writer = nullptr;
    TableVal* config = nullptr;
    TableVal* field_name_map = nullptr;
    string scope_sep;
    string ext_prefix;
    Func* ext_func = nullptr;
    int num_ext_fields = 0;
    bool local = false;
    bool remote = false;
    double interval = 0.0;
    Func* postprocessor = nullptr;

    int num_fields = 0;
    threading::Field** fields = nullptr;

    // Vector indexed by field number. Each element is a list of record
    // indices defining a path leading to the value across potential
    // sub-records.
    vector<list<int>> indices;

    ~Filter();
};

struct Manager::WriterInfo {
    EnumVal* type = nullptr;
    double open_time = 0.0;
    zeek::detail::Timer* rotation_timer = nullptr;
    double interval = 0.0;
    Func* postprocessor = nullptr;
    WriterFrontend* writer = nullptr;
    WriterBackend::WriterInfo* info = nullptr;
    bool from_remote = false;
    bool hook_initialized = false;
    string instantiating_filter;

    std::shared_ptr<telemetry::IntCounter> total_writes;

    WriterInfo(std::shared_ptr<telemetry::IntCounter> total_writes) : total_writes(std::move(total_writes)) {}
};

struct Manager::Stream {
    EnumVal* id = nullptr;
    bool enabled = false;
    string name;
    RecordType* columns = nullptr;
    EventHandlerPtr event;
    Func* policy = nullptr;
    list<Filter*> filters;

    using WriterPathPair = pair<zeek_int_t, string>;
    using WriterMap = map<WriterPathPair, WriterInfo*>;

    WriterMap writers; // Writers indexed by id/path pair.

    bool enable_remote = false;

    std::shared_ptr<telemetry::IntCounter> total_writes; // Initialized on first write.

    // State about delayed writes for this Stream.
    detail::DelayQueue delay_queue;
    detail::DelayTokenMap delay_tokens;
    detail::DelayWriteMap delayed_writes;
    detail::WriteIdx write_idx = 0;

    detail::LogDelayExpiredTimer* delay_timer = nullptr;
    double max_delay_interval = 0.0;
    zeek_uint_t max_delay_queue_size = 1;
    bool evicting = false;


    ~Stream();


    const detail::DelayInfoPtr& GetDelayInfo(const detail::WriteContext& ctx);

    void EnqueueWriteForDelay(const detail::WriteContext& ctx);
    void EvictDelayedWrites();
    void ScheduleLogDelayExpiredTimer(double t);
    void DispatchDelayExpiredTimer(double t, bool is_expire);
};

Manager::Filter::~Filter() {
    Unref(fval);
    Unref(field_name_map);
    Unref(writer);
    Unref(id);

    for ( int i = 0; i < num_fields; ++i )
        delete fields[i];

    free(fields);

    Unref(path_val);
    Unref(config);
}

Manager::Stream::~Stream() {
    Unref(columns);

    for ( WriterMap::iterator i = writers.begin(); i != writers.end(); i++ ) {
        WriterInfo* winfo = i->second;

        if ( winfo->rotation_timer )
            zeek::detail::timer_mgr->Cancel(winfo->rotation_timer);

        Unref(winfo->type);
        delete winfo->writer;
        delete winfo->info;
        delete winfo;
    }

    for ( list<Filter*>::iterator f = filters.begin(); f != filters.end(); ++f )
        delete *f;

    if ( delay_timer )
        zeek::detail::timer_mgr->Cancel(delay_timer);

    delay_timer = nullptr;
}

const detail::DelayInfoPtr& Manager::Stream::GetDelayInfo(const detail::WriteContext& ctx) {
    const auto& it = delayed_writes.find(ctx);
    if ( it != delayed_writes.end() )
        return it->second;

    return detail::DelayInfo::nil;
}

void Manager::Stream::EnqueueWriteForDelay(const detail::WriteContext& ctx) {
    const auto delay_info = GetDelayInfo(ctx);
    assert(delay_info != nullptr);
    const auto& position = delay_queue.insert(delay_queue.end(), delay_info);
    delay_info->SetQueuePosition(position);

    DBG_LOG(DBG_LOGGING, "Enqueue record %p with delay_refs=%d, expire_time=%lf", ctx.record.get(),
            delay_info->DelayRefs(), delay_info->ExpireTime());

    EvictDelayedWrites();

    // If all delays have already been resolved after Log::write() returned,
    // directly complete the delay.
    if ( ! delay_info->HasDelayRefs() ) {
        zeek::log_mgr->DelayCompleted(this, *delay_info);
        return;
    }

    ScheduleLogDelayExpiredTimer(delay_info->ExpireTime());
}

void Manager::Stream::EvictDelayedWrites() {
    // Prevent recursion as DelayCompleted() may call EnqueueWriteForDelay()
    // in turn calling into eviction.
    DBG_LOG(DBG_LOGGING, "EvictDelayedWrites queue_size=%ld max=%" PRIu64 " evicting=%d", delay_queue.size(),
            max_delay_queue_size, evicting);
    if ( evicting )
        return;

    evicting = true;

    if ( delay_queue.size() > max_delay_queue_size ) {
        if ( delay_timer ) {
            zeek::detail::timer_mgr->Cancel(delay_timer);
            delay_timer = nullptr;
        }

        // It may happen that all records are re-delayed, which we allow,
        // but also trigger a warning. This could be caused by indefinite
        // redelaying through post_delay_callbacks.
        auto start_queue_size = delay_queue.size();
        decltype(start_queue_size) current = 0;

        while ( delay_queue.size() > max_delay_queue_size ) {
            ++current;
            const auto& evict_delay_info = delay_queue.front();

            DBG_LOG(DBG_LOGGING, "Evicting record %p", evict_delay_info->Record().get());

            // Delay completed will remove it from the queue, no need to pop.
            zeek::log_mgr->DelayCompleted(this, *evict_delay_info);

            if ( current == start_queue_size ) {
                reporter->Warning("unable to evict delayed records for stream %s queue_size=%ld, all re-delayed?",
                                  id->GetType<EnumType>()->Lookup(id->InternalInt()), delay_queue.size());
                break;
            }
        }


        ScheduleLogDelayExpiredTimer(delay_queue.front()->ExpireTime());
    }

    evicting = false;
}

void Manager::Stream::ScheduleLogDelayExpiredTimer(double t) {
    if ( delay_timer != nullptr ) {
        assert(delay_timer->Time() <= t);
        return;
    }

    auto cb = [this](double ts, bool is_expire) { this->DispatchDelayExpiredTimer(ts, is_expire); };
    delay_timer = new detail::LogDelayExpiredTimer(cb, t);
    zeek::detail::timer_mgr->Add(delay_timer);
}

void Manager::Stream::DispatchDelayExpiredTimer(double t, bool is_expire) {
    delay_timer = nullptr;

    while ( ! delay_queue.empty() ) {
        const auto& delay_info = delay_queue.front();

        // If is_expire, drain the queue. Otherwise, stop
        // when the next record in the queue is in the future.
        if ( ! is_expire && delay_info->ExpireTime() > t )
            break;

        assert(delay_info->Record() != nullptr);
        DBG_LOG(DBG_LOGGING, "Delayed record %p expired", delay_info->Record().get());
        zeek::log_mgr->DelayCompleted(this, *delay_info);
    }

    // Re-arm the timer if there's more to do.
    if ( ! delay_queue.empty() )
        ScheduleLogDelayExpiredTimer(delay_queue.front()->ExpireTime());
}


Manager::Manager()
    : plugin::ComponentManager<logging::Component>("Log", "Writer"),
      total_log_stream_writes_family(telemetry_mgr->CounterFamily("zeek", "log-stream-writes", {"module", "stream"},
                                                                  "Total number of log writes for the given stream.",
                                                                  "1", true)),
      total_log_writer_writes_family(
          telemetry_mgr
              ->CounterFamily("zeek", "log-writer-writes", {"writer", "module", "stream", "filter-name", "path"},
                              "Total number of log writes passed to a concrete log writer not vetoed by stream or "
                              "filter policies.",
                              "1", true)) {
    rotations_pending = 0;
}

Manager::~Manager() {
    for ( vector<Stream*>::iterator s = streams.begin(); s != streams.end(); ++s )
        delete *s;
}

void Manager::InitPostScript() {
    rotation_format_func = id::find_func("Log::rotation_format_func");
    log_stream_policy_hook = id::find_func("Log::log_stream_policy");
}

WriterBackend* Manager::CreateBackend(WriterFrontend* frontend, EnumVal* tag) {
    Component* c = Lookup(tag);

    if ( ! c ) {
        reporter->Error("unknown writer type requested");
        return nullptr;
    }

    WriterBackend* backend = (*c->Factory())(frontend);
    assert(backend);

    return backend;
}

Manager::Stream* Manager::FindStream(EnumVal* id) {
    unsigned int idx = id->AsEnum();

    if ( idx >= streams.size() || ! streams[idx] )
        return nullptr;

    return streams[idx];
}

Manager::WriterInfo* Manager::FindWriter(WriterFrontend* writer) {
    for ( vector<Stream*>::iterator s = streams.begin(); s != streams.end(); ++s ) {
        if ( ! *s )
            continue;

        for ( Stream::WriterMap::iterator i = (*s)->writers.begin(); i != (*s)->writers.end(); i++ ) {
            WriterInfo* winfo = i->second;

            if ( winfo->writer == writer )
                return winfo;
        }
    }

    return nullptr;
}

bool Manager::CompareFields(const Filter* filter, const WriterFrontend* writer) {
    if ( filter->num_fields != writer->NumFields() )
        return false;

    for ( int i = 0; i < filter->num_fields; ++i )
        if ( filter->fields[i]->type != writer->Fields()[i]->type )
            return false;

    return true;
}

bool Manager::CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter) {
    if ( winfo->from_remote )
        // If the writer was instantiated as a result of remote logging, then
        // a filter and writer are only compatible if field types match
        return ! CompareFields(filter, winfo->writer);
    else
        // If the writer was instantiated locally, it is bound to one filter
        return winfo->instantiating_filter != filter->name;
}

void Manager::RemoveDisabledWriters(Stream* stream) {
    list<Stream::WriterPathPair> disabled;

    for ( Stream::WriterMap::iterator j = stream->writers.begin(); j != stream->writers.end(); j++ ) {
        if ( j->second->writer->Disabled() ) {
            j->second->writer->Stop();
            delete j->second;
            disabled.push_back(j->first);
        }
    }

    for ( list<Stream::WriterPathPair>::iterator j = disabled.begin(); j != disabled.end(); j++ )
        stream->writers.erase(*j);
}

bool Manager::CreateStream(EnumVal* id, RecordVal* sval) {
    if ( ! same_type(sval->GetType(), BifType::Record::Log::Stream, false) ) {
        reporter->Error("sval argument not of right type");
        return false;
    }

    RecordType* columns = sval->GetField("columns")->AsType()->AsTypeType()->GetType()->AsRecordType();

    bool log_attr_present = false;

    for ( int i = 0; i < columns->NumFields(); i++ ) {
        if ( ! (columns->FieldDecl(i)->GetAttr(zeek::detail::ATTR_LOG)) )
            continue;

        if ( ! threading::Value::IsCompatibleType(columns->GetFieldType(i).get()) ) {
            reporter->Error("type of field '%s' is not support for logging output", columns->FieldName(i));

            return false;
        }

        log_attr_present = true;
    }

    if ( ! log_attr_present ) {
        reporter->Error("logged record type does not have any &log attributes");
        return false;
    }

    const auto& event_val = sval->GetField("ev");
    Func* event = event_val ? event_val->AsFunc() : nullptr;

    const auto& policy_val = sval->GetField("policy");
    Func* policy = policy_val ? policy_val->AsFunc() : nullptr;

    if ( event ) {
        // Make sure the event is prototyped as expected.
        const auto& etype = event->GetType();

        if ( etype->Flavor() != FUNC_FLAVOR_EVENT ) {
            reporter->Error("stream event is a function, not an event");
            return false;
        }

        const auto& args = etype->ParamList()->GetTypes();

        if ( args.size() != 1 ) {
            reporter->Error("stream event must take a single argument");
            return false;
        }

        if ( ! same_type(args[0], columns) ) {
            reporter->Error("stream event's argument type does not match column record type");
            return false;
        }
    }

    // Make sure the vector has an entries for all streams up to the one
    // given.

    unsigned int idx = id->AsEnum();

    while ( idx >= streams.size() )
        streams.push_back(nullptr);

    if ( streams[idx] ) {
        // We already know this one. Clean up the old version before making
        // a new one.
        RemoveStream(idx);
    }

    // Create new stream.
    streams[idx] = new Stream;
    streams[idx]->id = id->Ref()->AsEnumVal();
    streams[idx]->enabled = true;
    streams[idx]->name = id->GetType()->AsEnumType()->Lookup(idx);
    streams[idx]->event = event ? event_registry->Lookup(event->Name()) : nullptr;
    streams[idx]->policy = policy;
    streams[idx]->columns = columns->Ref()->AsRecordType();
    streams[idx]->max_delay_interval = sval->GetField("max_delay_interval")->AsInterval();
    streams[idx]->max_delay_queue_size = sval->GetField("max_delay_queue_size")->AsCount();

    streams[idx]->enable_remote = id::find_val("Log::enable_remote_logging")->AsBool();

    DBG_LOG(DBG_LOGGING, "Created new logging stream '%s', raising event %s", streams[idx]->name.c_str(),
            event ? streams[idx]->event->Name() : "<none>");

    return true;
}

bool Manager::RemoveStream(EnumVal* id) {
    unsigned int idx = id->AsEnum();
    return RemoveStream(idx);
}

bool Manager::RemoveStream(unsigned int idx) {
    if ( idx >= streams.size() || ! streams[idx] )
        return false;

    Stream* stream = streams[idx];

    if ( ! stream )
        return false;

    for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ ) {
        WriterInfo* winfo = i->second;

        DBG_LOG(DBG_LOGGING, "Removed writer '%s' from stream '%s'", winfo->writer->Name(), stream->name.c_str());

        winfo->writer->Stop();
        delete winfo->writer;
        delete winfo;
    }

    stream->writers.clear();
    string sname(stream->name);
    delete stream;
    streams[idx] = nullptr;

    DBG_LOG(DBG_LOGGING, "Removed logging stream '%s'", sname.c_str());
    return true;
}

bool Manager::EnableStream(EnumVal* id) {
    Stream* stream = FindStream(id);

    if ( ! stream )
        return false;

    if ( stream->enabled )
        return true;

    stream->enabled = true;

    DBG_LOG(DBG_LOGGING, "Reenabled logging stream '%s'", stream->name.c_str());
    return true;
}

bool Manager::DisableStream(EnumVal* id) {
    Stream* stream = FindStream(id);

    if ( ! stream )
        return false;

    if ( ! stream->enabled )
        return true;

    stream->enabled = false;

    DBG_LOG(DBG_LOGGING, "Disabled logging stream '%s'", stream->name.c_str());
    return true;
}

// Helper for recursive record field unrolling.
bool Manager::TraverseRecord(Stream* stream, Filter* filter, RecordType* rt, TableVal* include, TableVal* exclude,
                             const string& path, const list<int>& indices) {
    // Only include extensions for the outer record.
    int num_ext_fields = (indices.size() == 0) ? filter->num_ext_fields : 0;

    int i = 0;
    for ( int j = 0; j < num_ext_fields + rt->NumFields(); ++j ) {
        RecordType* rtype;
        // If this is an ext field, set the rtype appropriately
        if ( j < num_ext_fields ) {
            i = j;
            rtype = filter->ext_func->GetType()->Yield()->AsRecordType();
        }
        else {
            i = j - num_ext_fields;
            rtype = rt;
        }

        const auto& t = rtype->GetFieldType(i);

        // Ignore if &log not specified.
        if ( ! rtype->FieldDecl(i)->GetAttr(zeek::detail::ATTR_LOG) )
            continue;

        list<int> new_indices = indices;
        new_indices.push_back(i);

        // Build path name.
        string new_path;

        if ( ! path.size() )
            new_path = rtype->FieldName(i);
        else
            new_path = path + filter->scope_sep + rtype->FieldName(i);

        // Add the ext prefix if this is an ext field.
        if ( j < num_ext_fields )
            new_path = filter->ext_prefix + new_path;

        if ( t->InternalType() == TYPE_INTERNAL_OTHER ) {
            if ( t->Tag() == TYPE_RECORD ) {
                // Recurse.
                if ( ! TraverseRecord(stream, filter, t->AsRecordType(), include, exclude, new_path, new_indices) )
                    return false;

                continue;
            }

            else if ( t->Tag() == TYPE_TABLE && t->AsTableType()->IsSet() ) {
                // That's ok, we handle it below.
            }

            else if ( t->Tag() == TYPE_VECTOR ) {
                // That's ok, we handle it below.
            }

            else if ( t->Tag() == TYPE_FILE ) {
                // That's ok, we handle it below.
            }

            else if ( t->Tag() == TYPE_FUNC ) {
                // That's ok, we handle it below.
            }

            else {
                reporter->Error("unsupported field type for log column");
                return false;
            }
        }

        // If include fields are specified, only include if explicitly listed.
        // Exception: extension fields provided by the filter's ext_func remain.
        if ( j >= num_ext_fields && include ) {
            auto new_path_val = make_intrusive<StringVal>(new_path.c_str());
            bool result = (bool)include->FindOrDefault(new_path_val);

            if ( ! result )
                continue;
        }

        // If exclude fields are specified, do not only include if listed.
        // Here too, extension fields always remain.
        if ( j >= num_ext_fields && exclude ) {
            auto new_path_val = make_intrusive<StringVal>(new_path.c_str());
            bool result = (bool)exclude->FindOrDefault(new_path_val);

            if ( result )
                continue;
        }

        // Alright, we want this field.
        filter->indices.push_back(new_indices);

        void* tmp = realloc(filter->fields, sizeof(threading::Field*) * (filter->num_fields + 1));

        if ( ! tmp ) {
            reporter->Error("out of memory in add_filter");
            return false;
        }

        ++filter->num_fields;
        filter->fields = (threading::Field**)tmp;

        TypeTag st = TYPE_VOID;

        if ( t->Tag() == TYPE_TABLE )
            st = t->AsSetType()->GetIndices()->GetPureType()->Tag();

        else if ( t->Tag() == TYPE_VECTOR )
            st = t->AsVectorType()->Yield()->Tag();

        bool optional = (bool)rtype->FieldDecl(i)->GetAttr(zeek::detail::ATTR_OPTIONAL);

        filter->fields[filter->num_fields - 1] =
            new threading::Field(new_path.c_str(), nullptr, t->Tag(), st, optional);
    }

    return true;
}

bool Manager::AddFilter(EnumVal* id, RecordVal* fval) {
    if ( ! same_type(fval->GetType(), BifType::Record::Log::Filter, false) ) {
        reporter->Error("filter argument not of right type");
        return false;
    }

    Stream* stream = FindStream(id);
    if ( ! stream )
        return false;

    // Find the right writer type.
    auto writer = fval->GetFieldOrDefault<EnumVal>("writer");

    // Create a new Filter instance.

    auto name = fval->GetFieldOrDefault("name");
    auto policy = fval->GetFieldOrDefault("policy");
    auto path_func = fval->GetFieldOrDefault("path_func");
    auto log_local = fval->GetFieldOrDefault("log_local");
    auto log_remote = fval->GetFieldOrDefault("log_remote");
    auto interv = fval->GetFieldOrDefault("interv");
    auto postprocessor = fval->GetFieldOrDefault("postprocessor");
    auto config = fval->GetFieldOrDefault("config");
    auto field_name_map = fval->GetFieldOrDefault("field_name_map");
    auto scope_sep = fval->GetFieldOrDefault("scope_sep");
    auto ext_prefix = fval->GetFieldOrDefault("ext_prefix");
    auto ext_func = fval->GetFieldOrDefault("ext_func");

    Filter* filter = new Filter;
    filter->fval = fval->Ref();
    filter->name = name->AsString()->CheckString();
    filter->id = id->Ref()->AsEnumVal();
    filter->policy = policy ? policy->AsFunc() : stream->policy;
    filter->path_func = path_func ? path_func->AsFunc() : nullptr;
    filter->writer = writer->Ref()->AsEnumVal();
    filter->local = log_local->AsBool();
    filter->remote = log_remote->AsBool();
    filter->interval = interv->AsInterval();
    filter->postprocessor = postprocessor ? postprocessor->AsFunc() : nullptr;
    filter->config = config->Ref()->AsTableVal();
    filter->field_name_map = field_name_map->Ref()->AsTableVal();
    filter->scope_sep = scope_sep->AsString()->CheckString();
    filter->ext_prefix = ext_prefix->AsString()->CheckString();
    filter->ext_func = ext_func ? ext_func->AsFunc() : nullptr;

    // Build the list of fields that the filter wants included, including
    // potentially rolling out fields.
    const auto& include = fval->GetField("include");
    const auto& exclude = fval->GetField("exclude");

    filter->num_ext_fields = 0;
    if ( filter->ext_func ) {
        if ( filter->ext_func->GetType()->Yield()->Tag() == TYPE_RECORD ) {
            filter->num_ext_fields = filter->ext_func->GetType()->Yield()->AsRecordType()->NumFields();
        }
        else if ( filter->ext_func->GetType()->Yield()->Tag() == TYPE_VOID ) {
            // This is a special marker for the default no-implementation
            // of the ext_func and we'll allow it to slide.
        }
        else {
            reporter->Error("Return value of log_ext is not a record (got %s)",
                            type_name(filter->ext_func->GetType()->Yield()->Tag()));
            delete filter;
            return false;
        }
    }

    filter->num_fields = 0;
    filter->fields = nullptr;
    if ( ! TraverseRecord(stream, filter, stream->columns, include ? include->AsTableVal() : nullptr,
                          exclude ? exclude->AsTableVal() : nullptr, "", list<int>()) ) {
        delete filter;
        return false;
    }

    // Get the path for the filter.
    auto path_val = fval->GetField("path");

    if ( path_val ) {
        filter->path = path_val->AsString()->CheckString();
        filter->path_val = path_val.release();
    }

    else {
        // If no path is given, it's derived based upon the value returned by
        // the first call to the filter's path_func (during first write).
        filter->path_val = nullptr;
    }

    // Remove any filter with the same name we might already have.
    RemoveFilter(id, filter->name);

    // Add the new one.
    stream->filters.push_back(filter);

#ifdef DEBUG
    ODesc desc;
    writer->Describe(&desc);

    DBG_LOG(DBG_LOGGING, "Created new filter '%s' for stream '%s'", filter->name.c_str(), stream->name.c_str());

    DBG_LOG(DBG_LOGGING, "   writer    : %s", desc.Description());
    DBG_LOG(DBG_LOGGING, "   path      : %s", filter->path.c_str());
    DBG_LOG(DBG_LOGGING, "   path_func : %s", (filter->path_func ? "set" : "not set"));
    DBG_LOG(DBG_LOGGING, "   policy    : %s", (filter->policy ? "set" : "not set"));

    for ( int i = 0; i < filter->num_fields; i++ ) {
        threading::Field* field = filter->fields[i];
        DBG_LOG(DBG_LOGGING, "   field %10s: %s", field->name, type_name(field->type));
    }
#endif

    return true;
}

bool Manager::RemoveFilter(EnumVal* id, StringVal* name) { return RemoveFilter(id, name->AsString()->CheckString()); }

bool Manager::RemoveFilter(EnumVal* id, const string& name) {
    Stream* stream = FindStream(id);
    if ( ! stream )
        return false;

    for ( list<Filter*>::iterator i = stream->filters.begin(); i != stream->filters.end(); ++i ) {
        if ( (*i)->name == name ) {
            Filter* filter = *i;
            stream->filters.erase(i);
            DBG_LOG(DBG_LOGGING, "Removed filter '%s' from stream '%s'", filter->name.c_str(), stream->name.c_str());
            delete filter;
            return true;
        }
    }

    // If we don't find the filter, we don't treat that as an error.
    DBG_LOG(DBG_LOGGING, "No filter '%s' for removing from stream '%s'", name.c_str(), stream->name.c_str());

    return true;
}

bool Manager::Write(EnumVal* id, RecordVal* columns_arg) {
    Stream* stream = FindStream(id);
    if ( ! stream )
        return false;

    if ( ! stream->enabled )
        return true;

    auto columns = columns_arg->CoerceTo({NewRef{}, stream->columns});

    if ( ! columns ) {
        reporter->Error("incompatible log record type");
        return false;
    }

    // Raise the log event.
    if ( stream->event )
        event_mgr.Enqueue(stream->event, columns);

    if ( ! stream->total_writes ) {
        std::string module_name = zeek::detail::extract_module_name(stream->name.c_str());
        std::initializer_list<telemetry::LabelView> labels{{"module", module_name}, {"stream", stream->name}};
        stream->total_writes = total_log_stream_writes_family->GetOrAdd(labels);
    }

    stream->total_writes->Inc();

    bool stream_veto = false;

    {
        // Scope for active write.
        uint64_t idx = ++stream->write_idx;
        detail::WriteContext active_write{{zeek::NewRef{}, id}, columns, idx};
        detail::ActiveWriteScope active_write_scope{active_writes, active_write};

        if ( log_stream_policy_hook ) {
            auto v = log_stream_policy_hook->Invoke(columns, IntrusivePtr{NewRef{}, id});
            if ( v && ! v->AsBool() ) {
                // We record the fact that this hook is vetoing
                // the write, but continue on to the filter-
                // level hooks to allow them to run anyway.
                // They cannot "un-veto".
                stream_veto = true;
            }
        }

        // Assert a Log::write() happening during the Log::log_stream_policy
        // didn't corrupt our notion of active_writes.
        assert(active_writes.back().record == active_write.record);
        assert(active_writes.back().idx == active_write.idx);

        if ( const auto& delay_info = stream->GetDelayInfo(active_write); delay_info ) {
            if ( ! stream_veto ) {
                DBG_LOG(DBG_LOGGING, "Active write %p was delayed", delay_info->Record().get());
                stream->EnqueueWriteForDelay(active_write);

                // We're done for now.
                return true;
            }

            // There's a stream veto, so we've never put anything into
            // the queue. Do the cleanup here and fall through to the
            // policy hooks.
            stream->delay_tokens.erase(detail::to_internal_delay_token(delay_info->TokenVal()));
            stream->delayed_writes.erase(active_writes.back());
        }
    } // scope for active write.

    return WriteToFilters(stream, std::move(columns), stream_veto ? PolicyVerdict::VETO : PolicyVerdict::PASS);
}

bool Manager::WriteToFilters(const Manager::Stream* stream, zeek::RecordValPtr columns, PolicyVerdict stream_verdict) {
    for ( auto* filter : stream->filters ) {
        string path = filter->path;

        // Policy hooks may veto the logging or alter the log
        // record if really necessary. Potential optimization:
        // don't invoke the hook at all when it has no
        // handlers/bodies. Doing this skips sampling and
        // plugin hooks, though, so for now we do invoke.
        if ( filter->policy ) {
            auto v = filter->policy->Invoke(columns, IntrusivePtr{NewRef{}, stream->id},
                                            IntrusivePtr{NewRef{}, filter->fval});
            if ( v && ! v->AsBool() )
                continue;
        }

        // Even if Log::log_stream_policy vetoed, we invoke filter policy
        // hooks. Skip actually writing here.
        if ( stream_verdict == PolicyVerdict::VETO )
            continue;

        if ( filter->path_func ) {
            ValPtr path_arg;

            if ( filter->path_val )
                path_arg = {NewRef{}, filter->path_val};
            else
                path_arg = val_mgr->EmptyString();

            ValPtr rec_arg;
            const auto& rt = filter->path_func->GetType()->Params()->GetFieldType("rec");

            if ( rt->Tag() == TYPE_RECORD )
                rec_arg = columns->CoerceTo(cast_intrusive<RecordType>(rt), true);
            else
                // Can be TYPE_ANY here.
                rec_arg = columns;

            auto v =
                filter->path_func->Invoke(IntrusivePtr{NewRef{}, stream->id}, std::move(path_arg), std::move(rec_arg));

            if ( ! v )
                return false;

            if ( v->GetType()->Tag() != TYPE_STRING ) {
                reporter->Error("path_func did not return string");
                return false;
            }

            if ( ! filter->path_val ) {
                filter->path = v->AsString()->CheckString();
                filter->path_val = v->Ref();
            }

            path = v->AsString()->CheckString();

#ifdef DEBUG
            DBG_LOG(DBG_LOGGING, "Path function for filter '%s' on stream '%s' return '%s'", filter->name.c_str(),
                    stream->name.c_str(), path.c_str());
#endif
        }

        Stream::WriterPathPair wpp(filter->writer->AsEnum(), path);

        // See if we already have a writer for this path.
        Stream::WriterMap::const_iterator w = stream->writers.find(wpp);

        if ( w != stream->writers.end() && CheckFilterWriterConflict(w->second, filter) ) {
            // Auto-correct path due to conflict over the writer/path pairs.
            string instantiator = w->second->instantiating_filter;
            string new_path;
            unsigned int i = 2;

            do {
                char num[32];
                snprintf(num, sizeof(num), "-%u", i++);
                new_path = path + num;
                wpp.second = new_path;
                w = stream->writers.find(wpp);
            } while ( w != stream->writers.end() && CheckFilterWriterConflict(w->second, filter) );

            Unref(filter->path_val);
            filter->path_val = new StringVal(new_path.c_str());

            reporter->Warning(
                "Write using filter '%s' on path '%s' changed to"
                " use new path '%s' to avoid conflict with filter '%s'",
                filter->name.c_str(), path.c_str(), new_path.c_str(), instantiator.c_str());

            path = filter->path = filter->path_val->AsString()->CheckString();
        }

        WriterBackend::WriterInfo* info = nullptr;
        WriterFrontend* writer = nullptr;

        if ( w != stream->writers.end() ) {
            // We know this writer already.
            writer = w->second->writer;
            info = w->second->info;

            if ( ! w->second->hook_initialized ) {
                auto wi = w->second;
                wi->hook_initialized = true;
                PLUGIN_HOOK_VOID(HOOK_LOG_INIT, HookLogInit(filter->writer->GetType()->AsEnumType()->Lookup(
                                                                filter->writer->InternalInt()),
                                                            wi->instantiating_filter, filter->local, filter->remote,
                                                            *wi->info, filter->num_fields, filter->fields));
            }
        }

        else {
            // No, need to create one.

            // Copy the fields for WriterFrontend::Init() as it
            // will take ownership.
            threading::Field** arg_fields = new threading::Field*[filter->num_fields];

            for ( int j = 0; j < filter->num_fields; ++j ) {
                // Rename fields if a field name map is set.
                if ( filter->field_name_map ) {
                    const char* name = filter->fields[j]->name;
                    if ( const auto& val = filter->field_name_map->Find(make_intrusive<StringVal>(name)) ) {
                        delete[] filter->fields[j]->name;
                        auto [data, len] = val->AsStringVal()->CheckStringWithSize();
                        filter->fields[j]->name = util::copy_string(data, len);
                    }
                }
                arg_fields[j] = new threading::Field(*filter->fields[j]);
            }

            info = new WriterBackend::WriterInfo;
            info->path = util::copy_string(path.c_str(), path.size());
            info->network_time = run_state::network_time;

            auto* filter_config_table = filter->config->AsTable();
            for ( const auto& fcte : *filter_config_table ) {
                auto k = fcte.GetHashKey();
                auto* v = fcte.value;

                auto index = filter->config->RecreateIndex(*k);
                string key = index->Idx(0)->AsString()->CheckString();
                string value = v->GetVal()->AsString()->CheckString();
                info->config.emplace(util::copy_string(key.c_str(), key.size()),
                                     util::copy_string(value.c_str(), value.size()));
            }

            // CreateWriter() will set the other fields in info.

            writer = CreateWriter(stream->id, filter->writer, info, filter->num_fields, arg_fields, filter->local,
                                  filter->remote, false, filter->name);

            if ( ! writer )
                return false;

            // Find the newly inserted WriterInfo record.
            w = stream->writers.find(wpp);
        }

        // Alright, can do the write now.

        threading::Value** vals = RecordToFilterVals(stream, filter, columns.get());

        if ( ! PLUGIN_HOOK_WITH_RESULT(HOOK_LOG_WRITE,
                                       HookLogWrite(filter->writer->GetType()->AsEnumType()->Lookup(
                                                        filter->writer->InternalInt()),
                                                    filter->name, *info, filter->num_fields, filter->fields, vals),
                                       true) ) {
            DeleteVals(filter->num_fields, vals);

#ifdef DEBUG
            DBG_LOG(DBG_LOGGING, "Hook prevented writing to filter '%s' on stream '%s'", filter->name.c_str(),
                    stream->name.c_str());
#endif
            return true;
        }

        assert(w != stream->writers.end());
        w->second->total_writes->Inc();

        // Write takes ownership of vals.
        assert(writer);
        writer->Write(filter->num_fields, vals);

#ifdef DEBUG
        DBG_LOG(DBG_LOGGING, "Wrote record to filter '%s' on stream '%s'", filter->name.c_str(), stream->name.c_str());
#endif
    }

    return true;
}

ValPtr Manager::Delay(const EnumValPtr& id, const RecordValPtr record, FuncPtr post_delay_cb) {
    if ( active_writes.size() == 0 ) {
        reporter->Error("invalid Log::delay() call: outside of Log::log_stream_policy() hook");
        return make_intrusive<detail::LogDelayTokenVal>();
    }

    const auto& active_write_ctx = active_writes.back();
    if ( active_write_ctx.id->Get() != id->Get() || active_write_ctx.record != record ) {
        reporter->Error("invalid Log::delay() call: argument mismatch with active Log::write()");
        return make_intrusive<detail::LogDelayTokenVal>();
    }

    DBG_LOG(DBG_LOGGING, "Delay() for %p RefCnt=%d", record.get(), record->RefCnt());

    ValPtr token_val;
    Stream* stream = FindStream(id.get());
    if ( ! stream )
        return make_intrusive<detail::LogDelayTokenVal>();

    if ( const auto& delay_info = stream->GetDelayInfo(active_write_ctx); delay_info ) {
        // Previously delayed, return the same token to script-land.
        token_val = delay_info->TokenVal();
        delay_info->IncDelayRefs();
        if ( post_delay_cb )
            delay_info->AppendPostDelayCallback(post_delay_cb);
    }
    else {
        // This is the first time this Log::write() is delayed, allocate a
        // new token and return it to script land.
        detail::DelayTokenType token = ++last_delay_token;
        token_val = zeek::make_intrusive<detail::LogDelayTokenVal>(token);
        double expire_time = run_state::network_time + stream->max_delay_interval;
        auto new_delay_info = std::make_shared<detail::DelayInfo>(active_write_ctx, token_val, expire_time);
        if ( post_delay_cb )
            new_delay_info->AppendPostDelayCallback(post_delay_cb);

        // Immediately keep information via the token, too, so that DelayFinish()
        // works right away (even directly after Delay().
        stream->delay_tokens[token] = new_delay_info;
        stream->delayed_writes.emplace(active_write_ctx, new_delay_info);

        assert(stream->GetDelayInfo(active_write_ctx) != detail::DelayInfo::nil);
    }

    DBG_LOG(DBG_LOGGING, "Delayed log record %p RefCnt=%d post_delay_cb=%p", record.get(), record->RefCnt(),
            post_delay_cb.get());

    return token_val;
}


bool Manager::DelayFinish(const EnumValPtr& id, const RecordValPtr& record, const ValPtr& token_val) {
    Stream* stream = FindStream(id.get());
    if ( ! stream )
        return false;

    if ( token_val->GetType()->Tag() != TYPE_OPAQUE ) {
        reporter->Error("invalid delay token type %s", zeek::type_name(token_val->GetType()->Tag()));
        return false;
    }

    const auto& token_type_name = token_val->GetType<zeek::OpaqueType>()->Name();
    if ( token_type_name != std::string_view{"LogDelayToken"} ) {
        reporter->Error("invalid Log::delay_finish() call: wrong opaque token type: %s", token_type_name.c_str());
        return false;
    }

    detail::DelayTokenType token = detail::to_internal_delay_token(token_val);
    if ( token == 0 ) {
        reporter->Error("invalid Log::delay_finish() call: invalid token provided");
        return false;
    }

    DBG_LOG(DBG_LOGGING, "DelayFinish() for %p RefCnt=%d token=%" PRIu64, record.get(), record->RefCnt(), token);
    const auto& it = stream->delay_tokens.find(token);

    if ( it == stream->delay_tokens.end() ) {
        reporter->Error("non-existing log record for token=%" PRIu64 " %p", token, record.get());
        return false;
    }

    auto& delay_info = it->second;

    if ( delay_info->Record() != record ) {
        reporter->Error("record mismatch token=%" PRIu64 " %p and %p", token, record.get(), delay_info->Record().get());
        return false;
    }

    if ( ! delay_info->HasDelayRefs() ) {
        reporter->Error("delay reference underflow for token=%" PRIu64, token);
        return false;
    }

    delay_info->DecDelayRefs();

    // Only call DelayCompleted() if this was ever properly enqueued.
    if ( delay_info->IsInQueue() && ! delay_info->HasDelayRefs() )
        DelayCompleted(stream, *delay_info);

    return true;
}

// Delaying has completed.
bool Manager::DelayCompleted(Stream* stream, detail::DelayInfo& delay_info) {
    auto token = detail::to_internal_delay_token(delay_info.TokenVal());
    assert(stream->delay_tokens.find(token) != stream->delay_tokens.end());

    DBG_LOG(DBG_LOGGING, "DelayCompleted() for log record %p RefCnt=%d token=%" PRIu64, delay_info.Record().get(),
            delay_info.Record()->RefCnt(), token);

    bool res = false;
    bool allow = true;

    {
        // Push a new active write when running the post delay callbacks. This
        // allows re-delaying the record and putting it at the end of the queue.
        uint64_t idx = ++stream->write_idx;
        detail::WriteContext write_context{delay_info.StreamId(), delay_info.Record(), idx};
        detail::ActiveWriteScope active_write_scope{active_writes, write_context};

        for ( const auto& cb : delay_info.PostDelayCallbacks() ) {
            auto v = cb->Invoke(delay_info.Record(), delay_info.StreamId());
            if ( v )
                allow &= v->AsBool();
        }

        DBG_LOG(DBG_LOGGING, "DelayCompleted() post_delay_callback for record %p outcome=%d", delay_info.Record().get(),
                allow);

        if ( const auto& new_delay_info = stream->GetDelayInfo(write_context); new_delay_info ) {
            // Post delay callbacks re-delayed, clean-up.
            stream->delay_queue.erase(delay_info.QueuePosition());
            stream->delay_tokens.erase(token);
            stream->delayed_writes.erase(delay_info.Context());

            DBG_LOG(DBG_LOGGING, "Enqueue re-delayed record %p as %" PRIu64 " (delay_refs=%d)",
                    new_delay_info->Record().get(), write_context.idx, new_delay_info->DelayRefs());
            stream->EnqueueWriteForDelay(write_context);
            return true;
        }
    }

    // If any of the callbacks vetoed, don't even let the filter policy hooks
    // see it. This is somewhat different from Log::log_stream_policy, but
    // seems somewhat saner.
    if ( allow )
        res = WriteToFilters(stream, delay_info.Record(), PolicyVerdict::PASS);

    // Clear the state.
    stream->delay_queue.erase(delay_info.QueuePosition());
    stream->delay_tokens.erase(token);
    stream->delayed_writes.erase(delay_info.Context());

    return res;
}

bool Manager::SetMaxDelayInterval(const EnumValPtr& id, double delay) {
    Stream* stream = FindStream(id.get());
    if ( ! stream )
        return false;

    DBG_LOG(DBG_LOGGING, "SetMaxDelayInterval: stream=%s max_delay=%f", stream->name.c_str(), delay);

    // We rely on script land to protect us from not setting a lower value.
    // Could consider to update the expiration time for all pending writes
    // the queue and start expiring from the head, too.

    if ( delay < stream->max_delay_interval ) {
        reporter->Warning("refusing to set lower delay %f < %f", delay, stream->max_delay_interval);
        return false;
    }

    stream->max_delay_interval = delay;

    return true;
}

zeek_int_t Manager::GetDelayQueueSize(const EnumValPtr& id) {
    Stream* stream = FindStream(id.get());
    if ( ! stream )
        return -1;

    return stream->delay_queue.size();
}

bool Manager::SetMaxDelayQueueSize(const EnumValPtr& id, zeek_uint_t queue_size) {
    Stream* stream = FindStream(id.get());
    if ( ! stream )
        return false;

    DBG_LOG(DBG_LOGGING, "SetMaxDelayQueueSize: stream=%s queue_size=%" PRIu64, stream->name.c_str(), queue_size);

    stream->max_delay_queue_size = queue_size;

    stream->EvictDelayedWrites();


    return true;
}

threading::Value* Manager::ValToLogVal(std::optional<ZVal>& val, Type* ty) {
    if ( ! val )
        return new threading::Value(ty->Tag(), false);

    threading::Value* lval = new threading::Value(ty->Tag());

    switch ( lval->type ) {
        case TYPE_BOOL:
        case TYPE_INT: lval->val.int_val = val->AsInt(); break;

        case TYPE_ENUM: {
            const char* s = ty->AsEnumType()->Lookup(val->AsInt());

            if ( s ) {
                auto len = strlen(s);
                lval->val.string_val.data = util::copy_string(s, len);
                lval->val.string_val.length = len;
            }

            else {
                auto err_msg = "enum type does not contain value:" + std::to_string(val->AsInt());
                ty->Error(err_msg.c_str());
                lval->val.string_val.data = util::copy_string("", 0);
                lval->val.string_val.length = 0;
            }
            break;
        }

        case TYPE_COUNT: lval->val.uint_val = val->AsCount(); break;

        case TYPE_PORT: {
            auto p = val->AsCount();

            auto pt = TRANSPORT_UNKNOWN;
            auto pm = p & PORT_SPACE_MASK;
            if ( pm == TCP_PORT_MASK )
                pt = TRANSPORT_TCP;
            else if ( pm == UDP_PORT_MASK )
                pt = TRANSPORT_UDP;
            else if ( pm == ICMP_PORT_MASK )
                pt = TRANSPORT_ICMP;

            lval->val.port_val.port = p & ~PORT_SPACE_MASK;
            lval->val.port_val.proto = pt;
            break;
        }

        case TYPE_SUBNET: val->AsSubNet()->Get().ConvertToThreadingValue(&lval->val.subnet_val); break;

        case TYPE_ADDR: val->AsAddr()->Get().ConvertToThreadingValue(&lval->val.addr_val); break;

        case TYPE_DOUBLE:
        case TYPE_TIME:
        case TYPE_INTERVAL: lval->val.double_val = val->AsDouble(); break;

        case TYPE_STRING: {
            const String* s = val->AsString()->AsString();
            char* buf = new char[s->Len()];
            memcpy(buf, s->Bytes(), s->Len());

            lval->val.string_val.data = buf;
            lval->val.string_val.length = s->Len();
            break;
        }

        case TYPE_FILE: {
            const File* f = val->AsFile();
            const char* s = f->Name();
            auto len = strlen(s);
            lval->val.string_val.data = util::copy_string(s, len);
            lval->val.string_val.length = len;
            break;
        }

        case TYPE_FUNC: {
            ODesc d;
            const Func* f = val->AsFunc();
            f->Describe(&d);
            const char* s = d.Description();
            auto len = strlen(s);
            lval->val.string_val.data = util::copy_string(s, len);
            lval->val.string_val.length = len;
            break;
        }

        case TYPE_TABLE: {
            auto tbl = val->AsTable();
            auto set = tbl->ToPureListVal();

            if ( ! set )
                // ToPureListVal has reported an internal warning
                // already. Just keep going by making something up.
                set = make_intrusive<ListVal>(TYPE_INT);

            auto tbl_t = cast_intrusive<TableType>(tbl->GetType());
            auto& set_t = tbl_t->GetIndexTypes()[0];
            bool is_managed = ZVal::IsManagedType(set_t);

            lval->val.set_val.size = set->Length();
            lval->val.set_val.vals = new threading::Value*[lval->val.set_val.size];

            for ( zeek_int_t i = 0; i < lval->val.set_val.size; i++ ) {
                std::optional<ZVal> s_i = ZVal(set->Idx(i), set_t);
                lval->val.set_val.vals[i] = ValToLogVal(s_i, set_t.get());
                if ( is_managed )
                    ZVal::DeleteManagedType(*s_i);
            }

            break;
        }

        case TYPE_VECTOR: {
            VectorVal* vec = val->AsVector();
            lval->val.vector_val.size = vec->Size();
            lval->val.vector_val.vals = new threading::Value*[lval->val.vector_val.size];

            auto& vv = vec->RawVec();
            auto& vt = vec->GetType()->Yield();

            for ( zeek_int_t i = 0; i < lval->val.vector_val.size; i++ ) {
                lval->val.vector_val.vals[i] = ValToLogVal(vv[i], vt.get());
            }

            break;
        }

        default: reporter->InternalError("unsupported type %s for log_write", type_name(lval->type));
    }

    return lval;
}

threading::Value** Manager::RecordToFilterVals(const Stream* stream, Filter* filter, RecordVal* columns) {
    RecordValPtr ext_rec;

    if ( filter->num_ext_fields > 0 ) {
        auto res = filter->ext_func->Invoke(IntrusivePtr{NewRef{}, filter->path_val});

        if ( res )
            ext_rec = {AdoptRef{}, res.release()->AsRecordVal()};
    }

    threading::Value** vals = new threading::Value*[filter->num_fields];

    for ( int i = 0; i < filter->num_fields; ++i ) {
        std::optional<ZVal> val;
        Type* vt;
        if ( i < filter->num_ext_fields ) {
            if ( ! ext_rec ) {
                // executing function did not return record. Send empty for all vals.
                vals[i] = new threading::Value(filter->fields[i]->type, false);
                continue;
            }

            val = ZVal(ext_rec.get());
            vt = ext_rec->GetType().get();
        }
        else {
            val = ZVal(columns);
            vt = columns->GetType().get();
        }

        // For each field, first find the right value, which can
        // potentially be nested inside other records.
        list<int>& indices = filter->indices[i];

        for ( list<int>::iterator j = indices.begin(); j != indices.end(); ++j ) {
            auto vr = val->AsRecord();
            val = vr->RawOptField(*j);

            if ( ! val ) {
                // Value, or any of its parents, is not set.
                vals[i] = new threading::Value(filter->fields[i]->type, false);
                break;
            }

            vt = cast_intrusive<RecordType>(vr->GetType())->GetFieldType(*j).get();
        }

        if ( val )
            vals[i] = ValToLogVal(val, vt);
    }

    return vals;
}

bool Manager::CreateWriterForRemoteLog(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info, int num_fields,
                                       const threading::Field* const* fields) {
    return CreateWriter(id, writer, info, num_fields, fields, true, false, true);
}

static void delete_info_and_fields(WriterBackend::WriterInfo* info, int num_fields,
                                   const threading::Field* const* fields) {
    for ( int i = 0; i < num_fields; i++ )
        delete fields[i];

    delete[] fields;
    delete info;
}

WriterFrontend* Manager::CreateWriter(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info, int num_fields,
                                      const threading::Field* const* fields, bool local, bool remote, bool from_remote,
                                      const string& instantiating_filter) {
    Stream* stream = FindStream(id);

    if ( ! stream ) {
        // Don't know this stream.
        delete_info_and_fields(info, num_fields, fields);
        return nullptr;
    }

    Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), info->path));

    if ( w != stream->writers.end() ) {
        // If we already have a writer for this. That's fine, we just
        // return it.
        delete_info_and_fields(info, num_fields, fields);
        return w->second->writer;
    }

    // Initialize metric for this frontend.
    std::string stream_module_name = zeek::detail::extract_module_name(stream->name.c_str());
    std::string writer_name = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());
    std::initializer_list<telemetry::LabelView> labels{{"writer", writer_name},
                                                       {"module", stream_module_name},
                                                       {"stream", stream->name},
                                                       {"filter-name", instantiating_filter},
                                                       {"path", info->path}};

    WriterInfo* winfo = new WriterInfo(zeek::log_mgr->total_log_writer_writes_family->GetOrAdd(labels));
    winfo->type = writer->Ref()->AsEnumVal();
    winfo->writer = nullptr;
    winfo->open_time = run_state::network_time;
    winfo->rotation_timer = nullptr;
    winfo->interval = 0;
    winfo->postprocessor = nullptr;
    winfo->info = info;
    winfo->from_remote = from_remote;
    winfo->hook_initialized = false;
    winfo->instantiating_filter = instantiating_filter;

    // Search for a corresponding filter for the writer/path pair and use its
    // rotation settings.  If no matching filter is found, fall back on
    // looking up the logging framework's default rotation interval.
    bool found_filter_match = false;
    list<Filter*>::const_iterator it;

    for ( it = stream->filters.begin(); it != stream->filters.end(); ++it ) {
        Filter* f = *it;
        if ( f->writer->AsEnum() == writer->AsEnum() && f->path == info->path ) {
            found_filter_match = true;
            winfo->interval = f->interval;
            winfo->postprocessor = f->postprocessor;

            if ( f->postprocessor ) {
                delete[] winfo->info->post_proc_func;
                winfo->info->post_proc_func = util::copy_string(f->postprocessor->Name());
            }

            break;
        }
    }

    if ( ! found_filter_match ) {
        const auto& interval = zeek::detail::global_scope()->Find("Log::default_rotation_interval");
        assert(id);
        winfo->interval = interval->GetVal()->AsInterval();

        if ( winfo->info->post_proc_func && strlen(winfo->info->post_proc_func) ) {
            auto func = id::find_func(winfo->info->post_proc_func);

            if ( func )
                winfo->postprocessor = func.get();
            else
                reporter->Warning("failed log postprocessor function lookup: %s\n", winfo->info->post_proc_func);
        }
    }

    stream->writers.insert(Stream::WriterMap::value_type(Stream::WriterPathPair(writer->AsEnum(), info->path), winfo));

    // Still need to set the WriterInfo's rotation parameters, which we
    // computed above.
    static auto log_rotate_base_time = id::find_val<StringVal>("log_rotate_base_time");
    static auto base_time = log_rotate_base_time->AsString()->CheckString();

    winfo->info->rotation_interval = winfo->interval;
    winfo->info->rotation_base = util::detail::parse_rotate_base_time(base_time);

    winfo->writer = new WriterFrontend(*winfo->info, id, writer, local, remote);
    winfo->writer->Init(num_fields, fields);

    if ( ! from_remote ) {
        winfo->hook_initialized = true;
        PLUGIN_HOOK_VOID(HOOK_LOG_INIT,
                         HookLogInit(writer->GetType()->AsEnumType()->Lookup(writer->InternalInt()),
                                     instantiating_filter, local, remote, *winfo->info, num_fields, fields));
    }

    InstallRotationTimer(winfo);

    return winfo->writer;
}

void Manager::DeleteVals(int num_fields, threading::Value** vals) {
    // Note this code is duplicated in WriterBackend::DeleteVals().
    for ( int i = 0; i < num_fields; i++ )
        delete vals[i];

    delete[] vals;
}

bool Manager::WriteFromRemote(EnumVal* id, EnumVal* writer, const string& path, int num_fields,
                              threading::Value** vals) {
    Stream* stream = FindStream(id);

    if ( ! stream ) {
        // Don't know this stream.
#ifdef DEBUG
        ODesc desc;
        id->Describe(&desc);
        DBG_LOG(DBG_LOGGING, "unknown stream %s in Manager::Write()", desc.Description());
#endif
        DeleteVals(num_fields, vals);
        return false;
    }

    if ( ! stream->enabled ) {
        DeleteVals(num_fields, vals);
        return true;
    }

    Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), path));

    if ( w == stream->writers.end() ) {
        // Don't know this writer.
#ifdef DEBUG
        ODesc desc;
        id->Describe(&desc);
        DBG_LOG(DBG_LOGGING, "unknown writer %s in Manager::Write()", desc.Description());
#endif
        DeleteVals(num_fields, vals);
        return false;
    }

    w->second->writer->Write(num_fields, vals);

    DBG_LOG(DBG_LOGGING, "Wrote pre-filtered record to path '%s' on stream '%s'", path.c_str(), stream->name.c_str());

    return true;
}

void Manager::SendAllWritersTo(const broker::endpoint_info& ei) {
    auto et = id::find_type("Log::Writer")->AsEnumType();

    for ( vector<Stream*>::iterator s = streams.begin(); s != streams.end(); ++s ) {
        Stream* stream = (*s);

        if ( ! (stream && stream->enable_remote) )
            continue;

        for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ ) {
            WriterFrontend* writer = i->second->writer;
            const auto& writer_val = et->GetEnumVal(i->first.first);
            broker_mgr->PublishLogCreate((*s)->id, writer_val.get(), *i->second->info, writer->NumFields(),
                                         writer->Fields(), ei);
        }
    }
}

bool Manager::SetBuf(EnumVal* id, bool enabled) {
    Stream* stream = FindStream(id);
    if ( ! stream )
        return false;

    for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
        i->second->writer->SetBuf(enabled);

    RemoveDisabledWriters(stream);

    return true;
}

bool Manager::Flush(EnumVal* id) {
    Stream* stream = FindStream(id);
    if ( ! stream )
        return false;

    if ( ! stream->enabled )
        return true;

    for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
        i->second->writer->Flush(run_state::network_time);

    RemoveDisabledWriters(stream);

    return true;
}

void Manager::Terminate() {
    for ( vector<Stream*>::iterator s = streams.begin(); s != streams.end(); ++s ) {
        if ( ! *s )
            continue;

        for ( Stream::WriterMap::iterator i = (*s)->writers.begin(); i != (*s)->writers.end(); i++ )
            i->second->writer->Stop();
    }
}

bool Manager::EnableRemoteLogs(EnumVal* stream_id) {
    auto stream = FindStream(stream_id);

    if ( ! stream )
        return false;

    stream->enable_remote = true;
    return true;
}

bool Manager::DisableRemoteLogs(EnumVal* stream_id) {
    auto stream = FindStream(stream_id);

    if ( ! stream )
        return false;

    stream->enable_remote = false;
    return true;
}

bool Manager::RemoteLogsAreEnabled(EnumVal* stream_id) {
    auto stream = FindStream(stream_id);

    if ( ! stream )
        return false;

    return stream->enable_remote;
}

RecordType* Manager::StreamColumns(EnumVal* stream_id) {
    auto stream = FindStream(stream_id);

    if ( ! stream )
        return nullptr;

    return stream->columns;
}

// Timer which on dispatching rotates the filter.
class RotationTimer final : public zeek::detail::Timer {
public:
    RotationTimer(double t, Manager::WriterInfo* arg_winfo, bool arg_rotate)
        : zeek::detail::Timer(t, zeek::detail::TIMER_ROTATE) {
        winfo = arg_winfo;
        rotate = arg_rotate;
    }

    ~RotationTimer() override;

    void Dispatch(double t, bool is_expire) override;

protected:
    Manager::WriterInfo* winfo;
    bool rotate;
};

RotationTimer::~RotationTimer() {
    if ( winfo->rotation_timer == this )
        winfo->rotation_timer = nullptr;
}

void RotationTimer::Dispatch(double t, bool is_expire) {
    winfo->rotation_timer = nullptr;

    if ( rotate )
        log_mgr->Rotate(winfo);

    if ( ! is_expire ) {
        winfo->open_time = run_state::network_time;
        log_mgr->InstallRotationTimer(winfo);
    }
}

void Manager::InstallRotationTimer(WriterInfo* winfo) {
    if ( run_state::terminating )
        return;

    if ( winfo->rotation_timer ) {
        zeek::detail::timer_mgr->Cancel(winfo->rotation_timer);
        winfo->rotation_timer = nullptr;
    }

    double rotation_interval = winfo->interval;

    if ( rotation_interval ) {
        // When this is called for the first time, zeek::run_state::network_time can still be
        // zero. If so, we set a timer which fires immediately but doesn't
        // rotate when it expires.
        if ( ! run_state::network_time )
            winfo->rotation_timer = new RotationTimer(1, winfo, false);
        else {
            if ( ! winfo->open_time )
                winfo->open_time = run_state::network_time;

            static auto log_rotate_base_time = id::find_val<StringVal>("log_rotate_base_time");
            static auto base_time = log_rotate_base_time->AsString()->CheckString();

            double base = util::detail::parse_rotate_base_time(base_time);
            double delta_t = util::detail::calc_next_rotate(run_state::network_time, rotation_interval, base);

            winfo->rotation_timer = new RotationTimer(run_state::network_time + delta_t, winfo, true);
        }

        zeek::detail::timer_mgr->Add(winfo->rotation_timer);

        DBG_LOG(DBG_LOGGING, "Scheduled rotation timer for %s to %.6f", winfo->writer->Name(),
                winfo->rotation_timer->Time());
    }
}

static std::string format_rotation_time_fallback(time_t t) {
    struct tm tm;
    char buf[128];
    const char* const date_fmt = "%y-%m-%d_%H.%M.%S";
    localtime_r(&t, &tm);
    strftime(buf, sizeof(buf), date_fmt, &tm);
    return buf;
}

std::string Manager::FormatRotationPath(EnumValPtr writer, std::string_view path, double open, double close,
                                        bool terminating, FuncPtr postprocessor) {
    auto ri = make_intrusive<RecordVal>(BifType::Record::Log::RotationFmtInfo);
    ri->Assign(0, std::move(writer));
    ri->Assign<StringVal>(1, path.size(), path.data());
    ri->AssignTime(2, open);
    ri->AssignTime(3, close);
    ri->Assign(4, terminating);
    ri->Assign<FuncVal>(5, std::move(postprocessor));

    std::string rval;
    ValPtr res = Val::nil;

    try {
        res = rotation_format_func->Invoke(ri);
    } catch ( InterpreterException& e ) {
        // Will have logged something, res continues to be nil
    }

    if ( res ) {
        auto rp_val = res->AsRecordVal();
        auto dir_val = rp_val->GetFieldOrDefault(0);
        auto prefix = rp_val->GetFieldAs<StringVal>(1)->CheckString();
        auto dir = dir_val->AsString()->CheckString();

        // If rotation_format_func returned an empty dir in RotationPath
        // and Log::default_logdir is set, use it so that rotation is
        // confined within it.
        auto default_logdir = zeek::id::find_const<StringVal>("Log::default_logdir")->ToStdString();
        if ( util::streq(dir, "") && ! default_logdir.empty() )
            dir = default_logdir.c_str();

        if ( ! util::streq(dir, "") && ! util::detail::ensure_intermediate_dirs(dir) ) {
            reporter->Error(
                "Failed to create dir '%s' returned by "
                "Log::rotation_format_func for path %.*s: %s",
                dir, static_cast<int>(path.size()), path.data(), strerror(errno));
            dir = "";
        }

        if ( util::streq(dir, "") )
            rval = prefix;
        else
            rval = util::fmt("%s/%s", dir, prefix);
    }
    else {
        auto rot_str = format_rotation_time_fallback((time_t)open);
        rval = util::fmt("%.*s-%s", static_cast<int>(path.size()), path.data(), rot_str.data());
        reporter->Error(
            "Failed to call Log::rotation_format_func for path %.*s "
            "continuing with rotation to: ./%s",
            static_cast<int>(path.size()), path.data(), rval.data());
    }

    return rval;
}

void Manager::Rotate(WriterInfo* winfo) {
    DBG_LOG(DBG_LOGGING, "Rotating %s at %.6f", winfo->writer->Name(), run_state::network_time);

    static auto default_ppf = id::find_func("Log::__default_rotation_postprocessor");

    FuncPtr ppf;

    if ( winfo->postprocessor )
        ppf = {NewRef{}, winfo->postprocessor};
    else
        ppf = default_ppf;

    auto rotation_path = FormatRotationPath({NewRef{}, winfo->type}, winfo->writer->Info().path, winfo->open_time,
                                            run_state::network_time, run_state::terminating, std::move(ppf));

    winfo->writer->Rotate(rotation_path.data(), winfo->open_time, run_state::network_time, run_state::terminating);

    ++rotations_pending;
}

bool Manager::FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name, double open,
                               double close, bool success, bool terminating) {
    assert(writer);

    --rotations_pending;

    if ( ! success ) {
        DBG_LOG(DBG_LOGGING, "Non-successful rotating writer '%s', file '%s' at %.6f,", writer->Name(), filename,
                run_state::network_time);
        return true;
    }

    DBG_LOG(DBG_LOGGING, "Finished rotating %s at %.6f, new name %s", writer->Name(), run_state::network_time,
            new_name);

    WriterInfo* winfo = FindWriter(writer);
    if ( ! winfo )
        return true;

    auto info = make_intrusive<RecordVal>(BifType::Record::Log::RotationInfo);
    info->Assign(0, {NewRef{}, winfo->type});
    info->Assign(1, new_name);
    info->Assign(2, winfo->writer->Info().path);
    info->AssignTime(3, open);
    info->AssignTime(4, close);
    info->Assign(5, terminating);

    static auto default_ppf = id::find_func("Log::__default_rotation_postprocessor");

    Func* func = winfo->postprocessor;

    if ( ! func )
        func = default_ppf.get();

    assert(func);

    // Call the postprocessor function.
    int result = 0;

    auto v = func->Invoke(std::move(info));
    if ( v )
        result = v->AsBool();

    return result;
}

} // namespace zeek::logging
