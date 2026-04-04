// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include <map>
#include <vector>

#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Notifier.h"
#include "zeek/Obj.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util.h"

namespace zeek {

class ODesc;
class Val;

using ValPtr = IntrusivePtr<Val>;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
} // namespace telemetry

namespace detail {

class Frame;
class Stmt;
class Expr;
class CallExpr;
class ID;
class WhenInfo;

using StmtPtr = IntrusivePtr<Stmt>;

namespace trigger {

// Triggers are the heart of "when" statements: expressions that when
// they become true execute a body of statements.

class TriggerTimer;
class TriggerTraversalCallback;

class Trigger final : public Obj, public notifier::detail::Receiver {
public:
    // Use this constructor via make_intrusive<...>. The usual pattern is
    // to then discard what's returned, i.e. "(void)make_intrusive<...>" -
    // however, a valid pointer will be returned that can be used for
    // subsequent method calls.
    //
    // The reason for this complexity is that if the trigger condition
    // is true upon construction, after construction finishes there's
    // no more to do and the object should be deleted (Unref()'d).
    // If the condition is not true, then the constructor ensures that
    // the object will be tracked via sufficient Ref()'ing for further
    // processing and eventual deletion once the trigger is satisfied
    // or times out.
    //
    // Note that this constructor differs from the deprecated one only
    // in where the "timeout" parameter appears, and in making the "loc"
    // parameter optional. ("loc" is only used for internal logging when
    // debugging triggers.)
    Trigger(const std::shared_ptr<WhenInfo>& wi, const IDSet& globals, std::vector<ValPtr> local_aggrs, double timeout,
            Frame* f, const Location* loc = nullptr);

    ~Trigger() override;

    // Evaluates the condition. If true, executes the body and deletes
    // the object.
    //
    // Returns the state of condition.
    bool Eval();

    // Executes timeout code and deletes the object.
    void Timeout();

    // Return the timeout interval (negative if none was specified).
    double TimeoutValue() const { return timeout_value; }

    // Called if another entity needs to complete its operations first
    // in any case before this trigger can proceed.
    void Hold() { delayed = true; }

    // Complement of Hold().
    void Release() { delayed = false; }

    // If we evaluate to true, our return value will be passed on
    // to the given trigger.  Note, automatically calls Hold().
    void Attach(Trigger* trigger);

    // Cache for return values of delayed function calls.  Returns whether
    // the trigger is queued for later evaluation -- it may not be queued
    // if the Val is null or it's disabled.  The cache is managed using
    // void*'s so that the value can be associated with either a CallExpr
    // (for interpreted execution) or a C++ function (for compiled-to-C++).
    //
    // Lookup() returned value must be Ref()'d if you want to hang onto it.
    bool Cache(const void* obj, Val* val);
    Val* Lookup(const void* obj);

    // Disable this trigger completely. Needed because Unref'ing the trigger
    // may not immediately delete it as other references may still exist.
    void Disable();

    bool Disabled() const { return disabled; }

    void Describe(ODesc* d) const override;

    // Overridden from Notifier.  We queue the trigger and evaluate it
    // later to avoid race conditions.
    void Modified(zeek::notifier::detail::Modifiable* m) override;

    // Overridden from notifier::Receiver.  If we're still waiting
    // on an ID/Val to be modified at termination time, we can't hope
    // for any further progress to be made, so just Unref ourselves.
    void Terminate() override;

    const char* Name() const { return name.c_str(); }

private:
    friend class TriggerTimer;

    void ReInit(const std::vector<ValPtr>& index_expr_results);

    void Register(const ID* id);
    void Register(Val* val);
    void UnregisterAll();

    ExprPtr cond;
    StmtPtr body;
    StmtPtr timeout_stmts;
    ExprPtr timeout;
    double timeout_value;
    Frame* frame;
    bool is_return;

    std::string name;

    TriggerTimer* timer;
    Trigger* attached;

    bool delayed; // true if a function call is currently being delayed
    bool disabled;

    // Globals and locals present in the when expression.
    IDSet globals;
    IDSet locals; // not needed, present only for matching deprecated logic

    // Tracks whether we've found the globals/locals, as the work only
    // has to be done once.
    bool have_trigger_elems = false;

    // Aggregate values seen in locals used in the trigger condition,
    // so we can detect changes in them that affect whether the condition
    // holds.
    std::vector<ValPtr> local_aggrs;

    std::vector<std::pair<Obj*, notifier::detail::Modifiable*>> objs;

    using ValCache = std::map<const void*, Val*>;
    ValCache cache;
};

class Manager final : public iosource::IOSource {
public:
    Manager();
    ~Manager() override;

    void InitPostScript();

    double GetNextTimeout() override;
    void Process() override;
    const char* Tag() override { return "TriggerMgr"; }

    void Queue(Trigger* trigger);

    struct Stats {
        unsigned long total;
        unsigned long pending;
    };

    void GetStats(Stats* stats);

private:
    using TriggerList = std::list<Trigger*>;
    TriggerList* pending;
    telemetry::CounterPtr trigger_count;
    telemetry::GaugePtr trigger_pending;
};

} // namespace trigger

extern trigger::Manager* trigger_mgr;

} // namespace detail
} // namespace zeek
