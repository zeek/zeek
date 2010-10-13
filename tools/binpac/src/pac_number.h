#ifndef pac_number_h
#define pac_number_h

#include "pac_common.h"

class Number : public Object
{
public:
	Number(int arg_n)
		: s(fmt("%d", arg_n)), n(arg_n) {}
	Number(const char* arg_s, int arg_n)
		: s(arg_s), n(arg_n) {}
	const char* Str() const 	{ return s.c_str(); }
	int Num() const 		{ return n; }

protected:
	const string s;
	const int n;
};

#endif  // pac_number_h
