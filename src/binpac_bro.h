#ifndef binpac_bro_h
#define binpac_bro_h

class Analyzer;
class Val;
class PortVal;

#include "util.h"
#include "Analyzer.h"
#include "Val.h"
#include "event.bif.func_h"

#include "binpac.h"

namespace binpac {

typedef Analyzer* BroAnalyzer;
typedef Val* BroVal;
typedef PortVal* BroPortVal;
typedef StringVal* BroStringVal;

inline StringVal* string_to_val(string const &str)
	{
	return new StringVal(str.c_str());
	}

inline StringVal* bytestring_to_val(const_bytestring const &str)
	{
	return new StringVal(str.length(), (const char*) str.begin());
	}

} // namespace binpac

extern int FLAGS_use_binpac;

#endif
