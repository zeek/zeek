#ifndef pac_enum_h
#define pac_enum_h

#include "pac_decl.h"

class Enum
	{
public:
	Enum(ID* id, Expr* expr = 0);
	~Enum();

	void GenHeader(Output* out_h, int* pval);

private:
	ID* id_;
	Expr* expr_;
	};

class EnumDecl : public Decl
	{
public:
	EnumDecl(ID* id, EnumList* enumlist);
	~EnumDecl() override;

	Type* DataType() const { return datatype_; }

	void Prepare() override;
	void GenForwardDeclaration(Output* out_h) override;
	void GenCode(Output* out_h, Output* out_cc) override;

private:
	EnumList* enumlist_;
	Type* datatype_;
	TypeDecl* extern_typedecl_;
	};

#endif // pac_enum_h
