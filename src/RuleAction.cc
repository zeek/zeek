// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RuleAction.h"

#include <algorithm>
#include <string>

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/RuleMatcher.h"
#include "zeek/Type.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"

using std::string;

namespace zeek::detail {

bool is_event(const char* id) { return zeek::event_registry->Lookup(id) != nullptr; }

RuleActionEvent::RuleActionEvent(const char* arg_msg)
    : msg(make_intrusive<StringVal>(arg_msg)), handler(signature_match), want_end_of_match(true) {}

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
    static const std::vector<zeek::TypePtr> signature_match_no_msg2_params = {signature_match_params[0],
                                                                              signature_match_params[2]};
    // Fabricated params for non-message event(state: signature_state, data: string, end_of_match: count)
    static const std::vector<zeek::TypePtr> signature_match_no_msg3_params = {signature_match_params[0],
                                                                              signature_match_params[2],
                                                                              signature_match_params[3]};

    if ( msg ) {
        // If msg was provided, the function signature needs to agree with
        // one of the signature_match() events that take the message.
        const auto& handler_args_rt = handler->GetType()->Params();
        auto prototype = signature_match->GetFunc()->GetType()->FindPrototype(*handler_args_rt);

        // No prototype matched, call CheckArgs() for those where at least
        // the number of arguments matches for better error messaging (if any).
        if ( ! prototype ) {
            for ( const auto& p : signature_match->GetType()->Prototypes() ) {
                if ( p.args->NumFields() != handler_args_rt->NumFields() )
                    continue;

                std::vector<TypePtr> tplist;
                std::for_each(p.args->Types()->begin(), p.args->Types()->end(),
                              [&tplist](const auto* td) { tplist.push_back(td->type); });

                (void)handler->GetType()->CheckArgs(tplist, true, true);
            }

            zeek::reporter->Error("wrong event parameters for '%s' (%s)", event_name,
                                  obj_desc_short(handler_args_rt.get()).c_str());
            return;
        }

        // signature_match(state, msg, data, [end_of_match])
        want_end_of_match = prototype->args->NumFields() > 3;
    }
    else {
        // When no message is provided, use non-message parameters.
        const auto& handler_args_rt = handler->GetType()->Params();
        want_end_of_match = handler_args_rt->NumFields() > 2;

        const auto& check_args =
            handler_args_rt->NumFields() == 2 ? signature_match_no_msg2_params : signature_match_no_msg3_params;

        if ( ! handler->GetFunc()->GetType()->CheckArgs(check_args, true, true) )
            zeek::reporter->Error("wrong event parameters for '%s'", event_name);
    }
}

void RuleActionEvent::DoAction(const Rule* parent, RuleEndpointState* state, const u_char* data, int len) {
    if ( handler ) {
        zeek::Args args;
        args.reserve(msg ? 3 : 2);
        args.emplace_back(AdoptRef{}, rule_matcher->BuildRuleStateValue(parent, state));

        if ( msg )
            args.emplace_back(msg);

        if ( data )
            args.emplace_back(make_intrusive<StringVal>(len, reinterpret_cast<const char*>(data)));
        else
            args.emplace_back(zeek::val_mgr->EmptyString());

        if ( want_end_of_match ) {
            auto* match = state->FindRulePatternMatch(parent);
            MatchPos end_of_match = (match != nullptr && data) ? match->end_of_match : 0;
            args.push_back(zeek::val_mgr->Count(end_of_match));
        }

        event_mgr.Enqueue(handler, std::move(args));
    }
}

void RuleActionEvent::PrintDebug() {
    fprintf(stderr, "	RuleActionEvent: |%s (%s)|\n", msg ? msg->CheckString() : "<none>", handler->Name());
}

RuleActionMIME::RuleActionMIME(const char* arg_mime, int arg_strength) : mime(arg_mime), strength(arg_strength) {}

void RuleActionMIME::PrintDebug() { fprintf(stderr, "	RuleActionMIME: |%s|\n", mime.c_str()); }

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
