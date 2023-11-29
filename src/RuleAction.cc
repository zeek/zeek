#include "zeek/RuleAction.h"

#include "zeek/zeek-config.h"

#include <string>

#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/RuleMatcher.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"

using std::string;

namespace zeek::detail {

RuleActionEvent::RuleActionEvent(const char* arg_msg)
    : msg(make_intrusive<StringVal>(arg_msg)), handler(signature_match) {}

RuleActionEvent::RuleActionEvent(const char* arg_msg, const char* event_name) {
    if ( arg_msg ) // Message can be null (not provided).
        msg = make_intrusive<StringVal>(arg_msg);

    handler = zeek::event_registry->Lookup(event_name);

    if ( ! handler ) {
        reporter->Error("unknown event '%s' specified in rule", event_name);
        return;
    }

    // Register non-script usage to make the UsageAnalyzer happy.
    zeek::event_registry->Register(event_name, false /*is_from_script*/);

    static const auto& signature_match_params = signature_match->GetFunc()->GetType()->ParamList()->GetTypes();
    // Fabricated params for non-message event(state: signature_state, data: string)
    static const std::vector<zeek::TypePtr> signature_match2_params = {signature_match_params[0],
                                                                       signature_match_params[2]};

    if ( msg ) {
        // If msg was provided, the function signature needs to agree with
        // the signature_match event, even if it's a different event.
        if ( ! handler->GetFunc()->GetType()->CheckArgs(signature_match_params, true, true) )
            zeek::reporter->Error("wrong event parameters for '%s'", event_name);
    }
    else {
        // When no message is provided, use non-message parameters.
        if ( ! handler->GetFunc()->GetType()->CheckArgs(signature_match2_params, true, true) )
            zeek::reporter->Error("wrong event parameters for '%s'", event_name);
    }
}
void RuleActionEvent::DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) {
    if ( handler ) {
        zeek::Args args;
        args.reserve(msg ? 3 : 2);
        args.push_back({AdoptRef{}, rule_matcher->BuildRuleStateValue(parent, state)});
        if ( msg )
            args.push_back(msg);
        if ( data )
            args.push_back(make_intrusive<StringVal>(len, reinterpret_cast<const char*>(data)));
        else
            args.push_back(zeek::val_mgr->EmptyString());

        event_mgr.Enqueue(handler, std::move(args));
    }
}

void RuleActionEvent::PrintDebug() {
    fprintf(stderr, "	RuleActionEvent: |%s (%s)|\n", msg ? msg->CheckString() : "<none>", handler->Name());
}

RuleActionMIME::RuleActionMIME(const char* arg_mime, int arg_strength) {
    mime = util::copy_string(arg_mime);
    strength = arg_strength;
}

void RuleActionMIME::PrintDebug() { fprintf(stderr, "	RuleActionMIME: |%s|\n", mime); }

RuleActionAnalyzer::RuleActionAnalyzer(const char* arg_analyzer) {
    string str(arg_analyzer);
    string::size_type pos = str.find(':');
    string arg = str.substr(0, pos);
    analyzer = analyzer_mgr->GetComponentTag(arg.c_str());

    if ( ! analyzer )
        reporter->Warning("unknown analyzer '%s' specified in rule", arg.c_str());

    if ( pos != string::npos ) {
        arg = str.substr(pos + 1);
        child_analyzer = analyzer_mgr->GetComponentTag(arg.c_str());

        if ( ! child_analyzer )
            reporter->Warning("unknown analyzer '%s' specified in rule", arg.c_str());
    }
    else
        child_analyzer = zeek::Tag();
}

void RuleActionAnalyzer::PrintDebug() {
    if ( ! child_analyzer )
        fprintf(stderr, "|%s|\n", analyzer_mgr->GetComponentName(analyzer).c_str());
    else
        fprintf(stderr, "|%s:%s|\n", analyzer_mgr->GetComponentName(analyzer).c_str(),
                analyzer_mgr->GetComponentName(child_analyzer).c_str());
}

void RuleActionEnable::DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) {
    if ( ! ChildAnalyzer() ) {
        if ( ! analyzer_mgr->IsEnabled(Analyzer()) )
            return;

        if ( state->PIA() )
            state->PIA()->ActivateAnalyzer(Analyzer(), parent);
    }
    else {
        if ( ! analyzer_mgr->IsEnabled(ChildAnalyzer()) )
            return;

        // This is ugly and works only if there exists only one
        // analyzer of each type.
        state->PIA()->AsAnalyzer()->Conn()->FindAnalyzer(Analyzer())->AddChildAnalyzer(ChildAnalyzer());
    }
}

void RuleActionEnable::PrintDebug() {
    fprintf(stderr, "  RuleActionEnable: ");
    RuleActionAnalyzer::PrintDebug();
}

void RuleActionDisable::DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) {
    if ( ! ChildAnalyzer() ) {
        if ( state->PIA() )
            state->PIA()->DeactivateAnalyzer(Analyzer());
    }
    else
        state->GetAnalyzer()->AddChildAnalyzer(state->GetAnalyzer()->FindChild(ChildAnalyzer()));
}

void RuleActionDisable::PrintDebug() {
    fprintf(stderr, "  RuleActionDisable: ");
    RuleActionAnalyzer::PrintDebug();
}

} // namespace zeek::detail
