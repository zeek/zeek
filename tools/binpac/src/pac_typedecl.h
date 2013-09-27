#ifndef pac_typedecl_h
#define pac_typedecl_h

#include "pac_decl.h"

class TypeDecl : public Decl
{
public:
	TypeDecl(ID *arg_id, ParamList *arg_params, Type *arg_type);
	~TypeDecl();
	void Prepare();
	void GenForwardDeclaration(Output *out_h);
	void GenCode(Output *out_h, Output *out_cc);

	Env *env() const	{ return env_; }
	Type *type() const	{ return type_; }
	string class_name() const;
	static Type *LookUpType(const ID *id);

protected:
	void AddParam(Param *param);
	virtual void AddBaseClass(vector<string> *base_classes) const {}
	void ProcessAttr(Attr *a);

	virtual void GenPubDecls(Output *out_h, Output *out_cc);
	virtual void GenPrivDecls(Output *out_h, Output *out_cc);
	virtual void GenInitCode(Output *out_cc);
	virtual void GenCleanUpCode(Output *out_cc);

	void GenConstructorFunc(Output *out_h, Output *out_cc);
	void GenDestructorFunc(Output *out_h, Output *out_cc);

	string ParseFuncPrototype(Env* env);
	void GenParseFunc(Output *out_h, Output *out_cc);

	void GenParsingEnd(Output *out_cc, Env *env, const DataPtr &data);

	void GenInitialBufferLengthFunc(Output *out_h, Output *out_cc);

protected:
	Env *env_;

	ParamList *params_;
	Type *type_;
};

#endif  // pac_typedecl_h
