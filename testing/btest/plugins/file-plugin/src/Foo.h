
#ifndef BRO_PLUGIN_DEMO_FOO_H
#define BRO_PLUGIN_DEMO_FOO_H

#include <Val.h>
#include <file_analysis/Analyzer.h>

namespace plugin {
namespace Demo_Foo {

class Foo : public file_analysis::Analyzer {
public:
	virtual bool DeliverStream(const u_char* data, uint64 len);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, file_analysis::File* file);

protected:
	Foo(RecordVal* args, file_analysis::File* file);
};

} }

#endif
