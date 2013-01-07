/**
 * BinPAC++ visitor that extracts information from an AST that we need later
 * for compiling.
 */

#ifndef BINPAC_PAC2AST_H
#define BINPAC_PAC2AST_H

#include <binpac/binpac++.h>

namespace bro {

namespace hilti {

/// That visitor that provides information extracted from an BinPAC++ AST.
class Pac2AST : ast::Visitor<binpac::AstInfo>
{
public:
	/// A struct recording information about a unit type found in a *.pac
	/// file.
	struct UnitInfo
		{
		string name;				// The fully-qualified name of the unit type.
		bool exported;				// True if the unit is exported.
		shared_ptr<binpac::type::Unit> unit;	// The unit's type.
		};

	typedef std::map<string, UnitInfo> unit_map;

	Pac2AST()	{}

	/**
	 * Walks the AST of one module. The walker accumulates information
	 * from all ASTs it has walked already, and makes the information
	 * available through the corresponding accessor methods.
	 */
	void process(shared_ptr<binpac::Module> module);

	/**
	 * Looks up a fully-qualified unit ID and returns the unit type if
	 * found, or null if not.
	 */
	shared_ptr<binpac::type::Unit> LookupUnit(const string& id);

	/**
	 * Returns a map of all units encountered so far, indexed by their
	 * fully-qualified unit names.
	 */
	const unit_map& Units() const	{ return units; }

private:
	void visit(binpac::Module* m) override;
	void visit(binpac::declaration::Type* t) override;

	unit_map units;
};

#endif

}

}
