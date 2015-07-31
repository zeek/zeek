
#ifndef BRO_PLUGIN_DEMO_FOO_H
#define BRO_PLUGIN_DEMO_FOO_H

#include <Val.h>
#include <iosource/PktSrc.h>

namespace plugin {
namespace Demo_Foo {

class Foo : public iosource::PktSrc {
public:
	Foo(const std::string& path, bool is_live);

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	virtual void Open();
	virtual void Close();
	virtual bool ExtractNextPacket(Packet* pkt);
	virtual void DoneWithPacket();
	virtual bool PrecompileFilter(int index, const std::string& filter);
	virtual bool SetFilter(int index);
	virtual void Statistics(Stats* stats);

private:
	Properties props;
	string packet;
};

}
}

#endif
