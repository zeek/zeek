// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Func.h"

#include <broker/error.hh>

#include "zeek/Desc.h"
#include "zeek/broker/Data.h"

namespace zeek::detail
	{

using namespace std;

unordered_map<p_hash_type, CompiledScript> compiled_scripts;
unordered_map<string, unordered_set<p_hash_type>> added_bodies;
unordered_map<p_hash_type, void (*)()> standalone_callbacks;
vector<void (*)()> standalone_activations;

void CPPFunc::Describe(ODesc* d) const
	{
	d->AddSP("compiled function");
	d->Add(name);
	}

CPPLambdaFunc::CPPLambdaFunc(string _name, FuncTypePtr ft, CPPStmtPtr _l_body)
	: ScriptFunc(move(_name), move(ft), {_l_body}, {0})
	{
	l_body = move(_l_body);
	}

broker::expected<broker::data> CPPLambdaFunc::SerializeClosure() const
	{
	auto vals = l_body->SerializeLambdaCaptures();

	broker::vector rval;
	rval.emplace_back(string("CopyFrame"));

	broker::vector body;

	for ( const auto& val : vals )
		{
		auto expected = Broker::detail::val_to_data(val.get());
		if ( ! expected )
			return broker::ec::invalid_data;

		TypeTag tag = val->GetType()->Tag();
		broker::vector val_tuple{move(*expected), static_cast<broker::integer>(tag)};
		body.emplace_back(move(val_tuple));
		}

	rval.emplace_back(move(body));

	return {move(rval)};
	}

void CPPLambdaFunc::SetCaptures(Frame* f)
	{
	l_body->SetLambdaCaptures(f);
	}

FuncPtr CPPLambdaFunc::DoClone()
	{
	return make_intrusive<CPPLambdaFunc>(name, type, l_body->Clone());
	}

	} // zeek::detail
