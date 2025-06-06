// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>

// Bytes used as Monte Carlo co-ordinates. This should be no more bits than the mantissa
// of your "double" floating point type.
constexpr int RT_MONTEN = 6;

namespace zeek {

class EntropyVal;

namespace detail {

class RandTest {
public:
    void add(const void* buf, int bufl);
    void end(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc, double* r_scc);

private:
    friend class zeek::EntropyVal;

    int64_t ccount[256] = {0}; /* Bins to count occurrences of values */
    int64_t totalc = 0;        /* Total bytes counted */
    int mp = 0;
    int sccfirst = 1;
    unsigned int monte[RT_MONTEN] = {0};

    int64_t inmont = 0;
    int64_t mcount = 0;

    double cexp = 0.0;
    double montex = 0.0;
    double montey = 0.0;
    double montepi = 0.0;
    double sccu0 = 0.0;
    double scclast = 0.0;
    double scct1 = 0.0;
    double scct2 = 0.0;
    double scct3 = 0.0;
};

} // namespace detail
} // namespace zeek
