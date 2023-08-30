// Capsulates local and remote event handlers.

#pragma once

#include <optional>
#include <string>
#include <unordered_set>

#include "zeek/Type.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h"

namespace zeek {

namespace run_state {
extern double network_time;
} // namespace run_state

namespace telemetry {
class IntCounter;
}

class Func;
using FuncPtr = IntrusivePtr<Func>;

class EventHandler {
public:
    explicit EventHandler(std::string name);

    const char* Name() const { return name.data(); }

    const FuncPtr& GetFunc() const { return local; }

    const FuncTypePtr& GetType(bool check_export = true);

    void SetFunc(FuncPtr f);

    void AutoPublish(std::string topic) { auto_publish.insert(std::move(topic)); }

    void AutoUnpublish(const std::string& topic) { auto_publish.erase(topic); }

    void Call(zeek::Args* vl, bool no_remote = false, double ts = run_state::network_time);

    // Returns true if there is at least one local or remote handler.
    explicit operator bool() const;

    [[deprecated("Remove in v7.1 - Unused event handlers are now found via UsageAnalyzer.")]] void SetUsed() {
        used = true;
    }
    [[deprecated("Remove in v7.1 - Unused event handlers are now found via UsageAnalyzer.")]] bool Used() const {
        return used;
    }

    // Handlers marked as error handlers will not be called recursively to
    // avoid infinite loops if they trigger a similar error themselves.
    void SetErrorHandler() { error_handler = true; }
    bool ErrorHandler() const { return error_handler; }

    void SetEnable(bool arg_enable) { enabled = arg_enable; }

    // Flags the event as interesting even if there is no body defined. In
    // particular, this will then still pass the event on to plugins.
    void SetGenerateAlways(bool arg_generate_always = true) { generate_always = arg_generate_always; }
    bool GenerateAlways() const { return generate_always; }

    uint64_t CallCount() const;

private:
    void NewEvent(zeek::Args* vl); // Raise new_event() meta event.

    std::string name;
    FuncPtr local;
    FuncTypePtr type;
    bool used; // this handler is indeed used somewhere
    bool enabled;
    bool error_handler; // this handler reports error messages.
    bool generate_always;

    // Initialize this lazy, so we don't expose metrics for 0 values.
    std::shared_ptr<zeek::telemetry::IntCounter> call_count;

    std::unordered_set<std::string> auto_publish;
};

// Encapsulates a ptr to an event handler to overload the boolean operator.
class EventHandlerPtr {
public:
    EventHandlerPtr(EventHandler* p = nullptr) { handler = p; }
    EventHandlerPtr(const EventHandlerPtr& h) { handler = h.handler; }

    const EventHandlerPtr& operator=(EventHandler* p) {
        handler = p;
        return *this;
    }
    const EventHandlerPtr& operator=(const EventHandlerPtr& h) {
        handler = h.handler;
        return *this;
    }

    bool operator==(const EventHandlerPtr& h) const { return handler == h.handler; }

    EventHandler* Ptr() { return handler; }

    explicit operator bool() const { return handler && *handler; }
    EventHandler* operator->() { return handler; }
    const EventHandler* operator->() const { return handler; }

private:
    EventHandler* handler;
};

} // namespace zeek
