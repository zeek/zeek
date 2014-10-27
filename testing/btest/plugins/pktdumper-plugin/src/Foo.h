
#ifndef BRO_PLUGIN_DEMO_FOO_H
#define BRO_PLUGIN_DEMO_FOO_H

#include <Val.h>
#include <iosource/PktDumper.h>

namespace plugin {
namespace Demo_Foo {

class Foo : public iosource::PktDumper {
public:
	Foo(const std::string& path, bool is_live);
	virtual ~Foo();

	static PktDumper* Instantiate(const std::string& path, bool append);

protected:
	virtual void Open();
	virtual void Close();
	virtual bool Dump(const Packet* pkt);

private:
	Properties props;
};

}
}

#endif
