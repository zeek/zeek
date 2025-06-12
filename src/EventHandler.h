// See the file "COPYING" in the main distribution directory for copyright.

// Capsulates local and remote event handlers.

#pragma once

#include <string>
#include <unordered_set>

#include "zeek/Type.h"
#include "zeek/ZeekArgs.h"

namespace zeek {

namespace run_state {
extern double network_time;
} // namespace run_state

namespace telemetry {
class Counter;
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

    [[deprecated("Remove in v8.1, use explicit Publish().")]]
    void AutoPublish(std::string topic) {
        auto_publish.insert(std::move(topic));
    }

    [[deprecated("Remove in v8.1.")]]
    void AutoUnpublish(const std::string& topic) {
        auto_publish.erase(topic);
    }

    [[deprecated(
        "Remove in v8.1. The no_remote and ts parameters are AutoPublish() specific and won't have an effect "
        "in the future. Use Call(args)")]]
    void Call(zeek::Args* vl, bool no_remote = false, double ts = run_state::network_time);

    // Call the function associated with this handler.
    void Call(zeek::Args* vl) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        Call(vl, false, run_state::network_time);
#pragma GCC diagnostic pop
    }

    // Returns true if there is at least one local or remote handler.
    explicit operator bool() const;

    // Handlers marked as error handlers will not be called recursively to
    // avoid infinite loops if they trigger a similar error themselves.
    void SetErrorHandler() { error_handler = true; }
    bool ErrorHandler() const { return error_handler; }

    void SetEnable(bool arg_enable) { enabled = arg_enable; }

    // Flags the event as interesting even if there is no body defined. In
    // particular, this will then still pass the event on to plugins.
    void SetGenerateAlways(bool arg_generate_always = true) { generate_always = arg_generate_always; }
    bool GenerateAlways() const { return generate_always; }

    // Returns the number of times this EventHandler has been called since startup.
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
    std::shared_ptr<zeek::telemetry::Counter> call_count;

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
        if ( this == &h )
            return *this;
        handler = h.handler;
        return *this;
    }

    bool operator==(const EventHandlerPtr& h) const { return handler == h.handler; }

    bool operator!=(const EventHandlerPtr& h) const { return ! (*this == h); }

    EventHandler* Ptr() { return handler; }

    explicit operator bool() const { return handler && *handler; }
    EventHandler* operator->() { return handler; }
    const EventHandler* operator->() const { return handler; }

private:
    EventHandler* handler;
};

} // namespace zeek
