#ifndef pac_utils_h
#define pac_utils_h

#include <sys/types.h>
#include <string>
using namespace std;

char* copy_string(const char* s);
string strfmt(const char* fmt, ...);
char* nfmt(const char* fmt, ...);

#endif /* pac_utils_h */
