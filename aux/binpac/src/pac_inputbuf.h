#ifndef pac_inputbuf_h
#define pac_inputbuf_h

#include "pac_datadep.h"
#include "pac_dataptr.h"

class Expr;

class InputBuffer : public Object, public DataDepElement
{
public:
	InputBuffer(Expr *expr);

	bool RequiresAnalyzerContext() const;
	DataPtr GenDataBeginEnd(Output *out_cc, Env *env);

protected:
	bool DoTraverse(DataDepVisitor *visitor);

private:
	Expr *expr_;
};

#endif // pac_inputbuf_h
