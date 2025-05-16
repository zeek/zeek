#ifndef pac_nullptr_h
#define pac_nullptr_h

#include "pac_common.h"

class Nullptr : public Object {
public:
    const char* Str() const { return s.c_str(); }

protected:
    const string s = "nullptr";
};

#endif // pac_nullptr_h
