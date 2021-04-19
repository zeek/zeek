// See the file "COPYING" in the main distribution directory for copyright.

#include <broker/error.hh>

#include "zeek/Desc.h"
#include "zeek/broker/Data.h"
#include "zeek/script_opt/CPP/Func.h"


namespace zeek::detail {

std::unordered_map<p_hash_type, CompiledScript> compiled_scripts;
std::unordered_map<p_hash_type, void (*)()> standalone_callbacks;
std::vector<void (*)()> standalone_activations;

void CPPFunc::Describe(ODesc* d) const
	{
	d->AddSP("compiled function");
	d->Add(name);
	}

CPPLambdaFunc::CPPLambdaFunc(std::string _name, FuncTypePtr ft,
				CPPStmtPtr _l_body)
: ScriptFunc(std::move(_name), std::move(ft), {_l_body}, {0})
	{
	l_body = std::move(_l_body);
	}

broker::expected<broker::data> CPPLambdaFunc::SerializeClosure() const
	{
	auto vals = l_body->SerializeLambdaCaptures();

	broker::vector rval;
	rval.emplace_back(std::string("CopyFrame"));

	broker::vector body;

	for ( int i = 0; i < vals.size(); ++i )
		{
		const auto& val = vals[i];
		auto expected = Broker::detail::val_to_data(val.get());
		if ( ! expected )
			return broker::ec::invalid_data;

		TypeTag tag = val->GetType()->Tag();
		broker::vector val_tuple {std::move(*expected),
		                          static_cast<broker::integer>(tag)};
		body.emplace_back(std::move(val_tuple));
		}

	rval.emplace_back(std::move(body));

	return {std::move(rval)};
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
