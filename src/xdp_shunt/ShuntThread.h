#include <zeek/IntrusivePtr.h>
#include <thread>

#include "bpf/UserXDP.h"

namespace xdp::shunter::detail {

class ShuntThread {
public:
    ShuntThread() = default;
    ShuntThread(struct filter* skel) : rb(make_shunt_fin_buffer(skel, handle_event)) {
        if ( ! rb )
            throw std::runtime_error("Failed to create ring buffer");

        poller = std::jthread([this](std::stop_token st) { this->poll_loop(st); });
    }
    ~ShuntThread() = default;

    ShuntThread(const ShuntThread&) = delete;
    ShuntThread& operator=(const ShuntThread&) = delete;
    ShuntThread(const ShuntThread&&) = delete;
    ShuntThread& operator=(const ShuntThread&&) = delete;

    static int handle_event(void* ctx, void* data, size_t data_sz);

private:
    void poll_loop(std::stop_token stoken) {
        while ( ! stoken.stop_requested() ) {
            poll_shunt_fin(rb.get(), 100);
        }
    }

    using RingBufferDeleter = decltype([](ring_buffer* ptr) { free_ring_buffer(ptr); });

    std::jthread poller;
    std::unique_ptr<ring_buffer, RingBufferDeleter> rb;
};

} // namespace xdp::shunter::detail
