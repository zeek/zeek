
#include "Pac2AST.h"

#include <binpac++.h>
#include <binpac/type.h>
#include <binpac/declaration.h>

using namespace bro::hilti;

void Pac2AST::process(shared_ptr<binpac::Module> module)
	{
	processAllPreOrder(module);
	}

shared_ptr<binpac::type::Unit> Pac2AST::LookupUnit(const string& id)
	{
	auto i = units.find(id);
	return i != units.end() ? i->second.unit : nullptr;
	}

void Pac2AST::visit(binpac::Module* u)
	{
	}

void Pac2AST::visit(binpac::declaration::Type* t)
	{
	shared_ptr<binpac::type::Unit> unit = ast::tryCast<binpac::type::Unit>(t->type());

	if ( ! unit )
		return;

	string name = t->id()->name();
	string fq = current<binpac::Module>()->id()->name() + "::" + name;

	UnitInfo uinfo;
	uinfo.name = fq;
	uinfo.exported = (t->linkage() == binpac::Declaration::EXPORTED);
	uinfo.unit = unit;

	units.insert(std::make_pair(fq, uinfo));
	}


