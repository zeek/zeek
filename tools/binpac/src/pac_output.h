// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_output_h
#define pac_output_h

#include <cstdarg>
#include <cstdio>
#include <exception>
#include <string>

using namespace std;

class OutputException : public std::exception {
public:
    OutputException(string arg_msg);
    [[deprecated("Remove in v9.1. Use what().")]]
    const char* errmsg() const {
        return msg.c_str();
    }
    const char* what() const noexcept override { return msg.c_str(); }

protected:
    string msg;
};

class Output {
public:
    Output(const string& filename);
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
