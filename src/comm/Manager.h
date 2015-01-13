#ifndef BRO_COMM_MANAGER_H
#define BRO_COMM_MANAGER_H

#include <broker/endpoint.hh>
#include <memory>
#include <string>
#include <map>
#include "Reporter.h"
#include "iosource/IOSource.h"

namespace comm {

// TODO: documentation

// Manages various forms of communication between peer Bro processes
// or possibly between different parts of a single Bro process.
class Manager : public iosource::IOSource {
public:

	bool InitPreScript();

	bool InitPostScript();

	bool Listen(uint16_t port, const char* addr = nullptr);

	bool Connect(std::string addr, uint16_t port,
	             std::chrono::duration<double> retry_interval);

	bool Disconnect(const std::string& addr, uint16_t port);

private:

	// IOSource interface overrides:
	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	            iosource::FD_Set* except) override;

	double NextTimestamp(double* local_network_time) override;

	void Process() override;

	const char* Tag() override
		{ return "Comm::Manager"; }

	std::unique_ptr<broker::endpoint> endpoint;
	std::map<std::pair<std::string, uint16_t>, broker::peering> peers;
};

} // namespace comm

extern comm::Manager* comm_mgr;

#endif // BRO_COMM_MANAGER_H
