
#pragma once

#include <Val.h>
#include <iosource/PktSrc.h>

namespace plugin {
namespace Demo_Foo {

class Foo : public iosource::PktSrc {
public:
	Foo(const std::string& path, bool is_live);

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	void Open() override;
	void Close() override;
	void HandleNewData(int fd) override;
	bool PrecompileFilter(int index, const std::string& filter) override;
	bool SetFilter(int index) override;
	void Statistics(Stats* stats) override;
	bool IsOpen() const override { return open; }

private:
	Properties props;
	string packet;
	bool open = false;
};

}
}
