#ifndef pac_context_h
#define pac_context_h

#include "pac_common.h"
#include "pac_field.h"
#include "pac_type.h"
#include "pac_typedecl.h"

// AnalyzerContext represents a cookie that an analyzer gives to
// parse functions of various message types. The cookie is parsed
// to every parse function (if necessary) as parameter 'binpac_context'.
// 
// The members of the cookie is declared through 'analyzer' declarations,
// such as in:
//
// analyzer SunRPC withcontext {
//        connection:     RPC_Conn;
//        flow:           RPC_Flow;
// };      
//
// The cookie usually contains the connection and flow in which 
// the message appears, and the context information can be 
// accessed as members of the cookie, such as 
// ``binpac_context.connection''.

class ContextField : public Field
{
public:
	ContextField(ID *id, Type *type);
};

class AnalyzerContextDecl : public TypeDecl
{
public:
	AnalyzerContextDecl(ID *id, ContextFieldList *context_fields);
	~AnalyzerContextDecl();

	void AddFlowBuffer();

	const ID *context_name_id() const { return context_name_id_; }

	// The type of analyzer context as a parameter
	ParameterizedType *param_type() const { return param_type_; }

	void GenForwardDeclaration(Output *out_h);
	void GenCode(Output *out_h, Output *out_cc);

	void GenNamespaceBegin(Output *out) const;
	void GenNamespaceEnd(Output *out) const;

private:
	ID *context_name_id_;
	ContextFieldList *context_fields_;
	ParameterizedType *param_type_;
	bool flow_buffer_added_;

// static members
public:
	static AnalyzerContextDecl *current_analyzer_context()
		{
		return current_analyzer_context_;
		}

	static string mb_buffer(Env *env);

private:
	static AnalyzerContextDecl *current_analyzer_context_;
};

class DummyType : public Type 
{
public:
	DummyType() : Type(DUMMY) {}

	bool DefineValueVar() const 	{ return false; }
	string DataTypeStr() const 	{ ASSERT(0); return ""; }

	int StaticSize(Env* env) const 	{ ASSERT(0); return -1; }

	bool ByteOrderSensitive() const { return false; }

	bool IsPointerType() const 	{ ASSERT(0); return false; }

	void DoGenParseCode(Output* out, Env* env,
			const DataPtr& data, int flags)
		{ ASSERT(0); }

	// Generate code for computing the dynamic size of the type
	void GenDynamicSize(Output* out, Env* env, const DataPtr& data)
		{ ASSERT(0); }

protected:
	Type *DoClone()	const;
	void DoMarkIncrementalInput()		{ ASSERT(0); }
};

#endif  // pac_context_h
