// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <string>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Tag.h"

namespace zeek {

class StringVal;
using StringValPtr = IntrusivePtr<StringVal>;

namespace detail {

class Rule;
class RuleEndpointState;

// Returns true if the given C-string represents a registered event.
bool is_event(const char* id);

// Base class of all rule actions.
class RuleAction {
public:
    RuleAction() {}
    virtual ~RuleAction() {}

    virtual void DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) = 0;
    virtual void PrintDebug() = 0;
};

// Implements the "event" keyword.
class RuleActionEvent : public RuleAction {
public:
    explicit RuleActionEvent(const char* arg_msg);
    explicit RuleActionEvent(const char* arg_msg, const char* event_name);

    void DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;

private:
    StringValPtr msg;
    EventHandlerPtr handler;
    bool want_end_of_match = false; // Whether handler accepts end_of_match parameter.
};

class RuleActionMIME : public RuleAction {
public:
    explicit RuleActionMIME(const char* arg_mime, int arg_strength = 0);

    void DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) override {}

    void PrintDebug() override;

    const std::string& GetMIME() const { return mime; }

    int GetStrength() const { return strength; }

private:
    std::string mime;
    int strength = 0;
};

// Base class for enable/disable actions.
class RuleActionAnalyzer : public RuleAction {
public:
    explicit RuleActionAnalyzer(const char* analyzer);

    void DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) override = 0;

    void PrintDebug() override;

    zeek::Tag Analyzer() const { return analyzer; }
    zeek::Tag ChildAnalyzer() const { return child_analyzer; }

private:
    zeek::Tag analyzer;
    zeek::Tag child_analyzer;
};

class RuleActionEnable : public RuleActionAnalyzer {
public:
    explicit RuleActionEnable(const char* analyzer) : RuleActionAnalyzer(analyzer) {}

    void DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;
};

class RuleActionDisable : public RuleActionAnalyzer {
public:
    explicit RuleActionDisable(const char* analyzer) : RuleActionAnalyzer(analyzer) {}

    void DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;
};

} // namespace detail
} // namespace zeek
