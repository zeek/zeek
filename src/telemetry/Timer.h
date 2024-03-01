// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <chrono>

#include "zeek/telemetry/Histogram.h"

namespace zeek::telemetry {

/// Convenience helper for measuring durations such as latency using a histogram
/// with second resolution. The measurement starts when creating the objects and
/// finishes when the Timer goes out of scope.
class [[nodiscard]] Timer {
public:
    using Clock = std::chrono::steady_clock;

    explicit Timer(std::shared_ptr<DblHistogram> h) : h_(std::move(h)) { start_ = Clock::now(); }

    Timer(const Timer&) = delete;

    Timer& operator=(const Timer&) = delete;

    ~Timer() { Observe(h_, start_); }

    /// @return The histogram handle.
    auto Handle() const noexcept { return h_; }

    /// @return The recorded start time.
    auto Started() const noexcept { return start_; }

    /// Calls `h.Observe` with the time passed since `start`.
    static void Observe(const std::shared_ptr<DblHistogram>& h, Clock::time_point start) {
        using DblSec = std::chrono::duration<double>;
        if ( auto end = Clock::now(); end > start )
            h->Observe(std::chrono::duration_cast<DblSec>(end - start).count());
    }

private:
    std::shared_ptr<DblHistogram> h_;
    Clock::time_point start_;
};

} // namespace zeek::telemetry
