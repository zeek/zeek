#include <string>
using std::string;

#include "zeek-config.h"

#include "RuleAction.h"
#include "RuleMatcher.h"
#include "Conn.h"
#include "Event.h"
#include "NetVar.h"
#include "analyzer/protocol/pia/PIA.h"

#include "analyzer/Manager.h"

namespace zeek::detail {

RuleActionEvent::RuleActionEvent(const char* arg_msg)
	{
	msg = zeek::util::copy_string(arg_msg);
	}

void RuleActionEvent::DoAction(const Rule* parent, RuleEndpointState* state,
                               const u_char* data, int len)
	{
	if ( signature_match )
		zeek::event_mgr.Enqueue(
			signature_match,
			zeek::IntrusivePtr{zeek::AdoptRef{}, rule_matcher->BuildRuleStateValue(parent, state)},
			zeek::make_intrusive<zeek::StringVal>(msg),
			data ? zeek::make_intrusive<zeek::StringVal>(len, (const char*)data) : zeek::val_mgr->EmptyString()
		);
	}

void RuleActionEvent::PrintDebug()
	{
	fprintf(stderr, "	RuleActionEvent: |%s|\n", msg);
	}

RuleActionMIME::RuleActionMIME(const char* arg_mime, int arg_strength)
	{
	mime = zeek::util::copy_string(arg_mime);
	strength = arg_strength;
	}

void RuleActionMIME::PrintDebug()
	{
	fprintf(stderr, "	RuleActionMIME: |%s|\n", mime);
	}

RuleActionAnalyzer::RuleActionAnalyzer(const char* arg_analyzer)
	{
	string str(arg_analyzer);
	string::size_type pos = str.find(':');
	string arg = str.substr(0, pos);
	analyzer = zeek::analyzer_mgr->GetComponentTag(arg.c_str());

	if ( ! analyzer )
		zeek::reporter->Warning("unknown analyzer '%s' specified in rule", arg.c_str());

	if ( pos != string::npos )
		{
		arg = str.substr(pos + 1);
		child_analyzer = zeek::analyzer_mgr->GetComponentTag(arg.c_str());

		if ( ! child_analyzer )
			zeek::reporter->Warning("unknown analyzer '%s' specified in rule", arg.c_str());
		}
	else
		child_analyzer = zeek::analyzer::Tag();
	}

void RuleActionAnalyzer::PrintDebug()
	{
	if ( ! child_analyzer )
		fprintf(stderr, "|%s|\n", zeek::analyzer_mgr->GetComponentName(analyzer).c_str());
	else
		fprintf(stderr, "|%s:%s|\n",
		        zeek::analyzer_mgr->GetComponentName(analyzer).c_str(),
		        zeek::analyzer_mgr->GetComponentName(child_analyzer).c_str());
	}


void RuleActionEnable::DoAction(const Rule* parent, RuleEndpointState* state,
                                const u_char* data, int len)
	{
	if ( ! ChildAnalyzer() )
		{
		if ( ! zeek::analyzer_mgr->IsEnabled(Analyzer()) )
			return;

		if ( state->PIA() )
			state->PIA()->ActivateAnalyzer(Analyzer(), parent);
		}
	else
		{
		if ( ! zeek::analyzer_mgr->IsEnabled(ChildAnalyzer()) )
			return;

		// This is ugly and works only if there exists only one
		// analyzer of each type.
		state->PIA()->AsAnalyzer()->Conn()->FindAnalyzer(Analyzer())
			->AddChildAnalyzer(ChildAnalyzer());
		}
	}

void RuleActionEnable::PrintDebug()
	{
	fprintf(stderr, "  RuleActionEnable: ");
	RuleActionAnalyzer::PrintDebug();
	}

void RuleActionDisable::DoAction(const Rule* parent, RuleEndpointState* state,
                                 const u_char* data, int len)
	{
	if ( ! ChildAnalyzer() )
		{
		if ( state->PIA() )
			state->PIA()->DeactivateAnalyzer(Analyzer());
		}
	else
		state->GetAnalyzer()->AddChildAnalyzer(
			state->GetAnalyzer()->FindChild(ChildAnalyzer()));
	}

void RuleActionDisable::PrintDebug()
	{
	fprintf(stderr, "  RuleActionDisable: ");
	RuleActionAnalyzer::PrintDebug();
	}

} // namespace zeek::detail
