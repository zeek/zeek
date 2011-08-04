#ifndef pac_output_h
#define pac_output_h

#include <stdio.h>
#include <stdarg.h>
#include <string>

using namespace std;

class OutputException {
public:
	OutputException(const char* arg_msg);
	~OutputException();
	const char* errmsg() const { return msg.c_str(); }

protected:
	string msg;
};

class Output {
public:
	Output(const char *filename);
	~Output();

	int println(const char* fmt, ...);
	int print(const char* fmt, ...);

	int indent() const { return indent_; }

	void inc_indent() { ++indent_; }
	void dec_indent() { --indent_; }

protected:
	int print(const char* fmt, va_list ap);

	FILE* fp;
	int indent_;
};

#endif /* pac_output_h */
