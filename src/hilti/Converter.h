///
/// Code to convert between HILTI and Bro values/types.
///

#ifndef BRO_HILTI_CONVERTER_H
#define BRO_HILTI_CONVERTER_H

#include <hilti/hilti.h>
#include <binpac/binpac++.h>

class BroType;

namespace hilti {
	class Expression;
	namespace builder	{
		class ModuleBuilder;
	}
}

namespace bro {

namespace hilti {

// Converts from BinPAC++ types to Bro types.
class TypeConverter : ast::Visitor<::hilti::AstInfo, BroType*, shared_ptr<::binpac::Type>>
{
public:
	TypeConverter();

	/**
	 * Converts a HILTI type into a Bro type. Aborts for unsupported
	 * types.
	 *
	 * @param type The HILTI type to convert.
	 *
	 * @param btype An optional BinPAC++ type that \a type may correspond to.
	 *
	 * @return The newly allocated Bro type.
	 */
	BroType* Convert(std::shared_ptr<::hilti::Type> type, std::shared_ptr<::binpac::Type> btype = nullptr);

private:
	void visit(::hilti::type::Bytes* b) override;
	void visit(::hilti::type::Reference* b) override;
};

// Converts from HILTI values to Bro values.
class ValueConverter : ast::Visitor<::hilti::AstInfo, bool, shared_ptr<::hilti::Expression>, shared_ptr<::hilti::Expression>>
{
public:
	ValueConverter(shared_ptr<::hilti::builder::ModuleBuilder> mbuilder);

	/**
	 * Generates HILTI code to convert a HILTI value into a Bro Val.
	 * Aborts for unsupported types.
	 *
	 * @param mbuilder The module builder to use; the code will be
	 * generated at its current building position.
	 *
	 * @param value The HILTI value to convert.
	 *
	 * @param dst A HILTI expression referencing the location where to store the converted value.
	 *
	 * @param btype An optional BinPAC++ type that \a value may correspond to.
	 *
	 * @returns True if the conversion was successul.
	 */
	bool Convert(shared_ptr<::hilti::Expression> value, shared_ptr<::hilti::Expression> dst, std::shared_ptr<::binpac::Type> btype = nullptr);

protected:
	/**
	 * Returns the BinPAC++ type passed \a Convert() during visiting; null if none.
	 */
	shared_ptr<::binpac::Type> arg3() const;

	/**
	 * Returns the current block builder.
	 */
	shared_ptr<::hilti::builder::BlockBuilder> Builder() const;

private:
	void visit(::hilti::type::Bytes* b) override;
	void visit(::hilti::type::Reference* b) override;

	shared_ptr<::hilti::builder::ModuleBuilder> mbuilder;
	shared_ptr<::binpac::Type> _arg3 = nullptr;
};

}

}

#endif
