
#ifndef ANALYZER_BUILTIN_ANALYZERS_H
#define ANALYZER_BUILTIN_ANALYZERS_H

#include "plugin/Plugin.h"

namespace analyzer {

class BuiltinAnalyzers : public plugin::Plugin {
public:
	virtual void Init();
};

}


#endif
