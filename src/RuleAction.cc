// $Id: RuleAction.cc 5906 2008-07-03 19:52:50Z vern $

#include <string>
using std::string;

#include "config.h"

#include "RuleAction.h"
#include "RuleMatcher.h"
#include "Conn.h"
#include "Event.h"
#include "NetVar.h"
#include "DPM.h"
#include "PIA.h"

void RuleActionEvent::DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len)
	{
	if ( signature_match )
		{
		val_list* vl = new val_list;
		vl->append(rule_matcher->BuildRuleStateValue(parent, state));
		vl->append(new StringVal(msg));

		if ( data )
			vl->append(new StringVal(len, (const char*)data));
		else
			vl->append(new StringVal(""));

		mgr.QueueEvent(signature_match, vl);
		}
	}

void RuleActionEvent::PrintDebug()
	{
	fprintf(stderr, "	RuleActionEvent: |%s|\n", msg);
	}

RuleActionDPM::RuleActionDPM(const char* arg_analyzer)
	{
	string str(arg_analyzer);
	string::size_type pos = str.find(':');
	string arg = str.substr(0, pos);
	analyzer = Analyzer::GetTag(arg.c_str());

	if ( pos != string::npos )
		{
		arg = str.substr(pos + 1);
		child_analyzer = Analyzer::GetTag(arg.c_str());
		}
	else
		child_analyzer = AnalyzerTag::Error;

	if ( analyzer != AnalyzerTag::Error )
		dpm->ActivateSigs();
	}

void RuleActionDPM::PrintDebug()
	{
	if ( child_analyzer == AnalyzerTag::Error )
		fprintf(stderr, "|%s|\n", Analyzer::GetTagName(analyzer));
	else
		fprintf(stderr, "|%s:%s|\n",
			Analyzer::GetTagName(analyzer),
			Analyzer::GetTagName(child_analyzer));
	}


void RuleActionEnable::DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len)
	{
	if ( ChildAnalyzer() == AnalyzerTag::Error )
		{
		if ( ! Analyzer::IsAvailable(Analyzer()) )
			return;

		if ( state->PIA() )
			state->PIA()->ActivateAnalyzer(Analyzer(), parent);
		}
	else
		{
		if ( ! Analyzer::IsAvailable(ChildAnalyzer()) )
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
	RuleActionDPM::PrintDebug();
	}

void RuleActionDisable::DoAction(const Rule* parent, RuleEndpointState* state,
					const u_char* data, int len)
	{
	if ( ChildAnalyzer() == AnalyzerTag::Error )
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
	RuleActionDPM::PrintDebug();
	}
