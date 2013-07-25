// Copyright 2004, 2005
// The Regents of the University of California
// All Rights Reserved
// 
// Permission to use, copy, modify and distribute any part of this
// h3.h file, without fee, and without a written agreement is hereby
// granted, provided that the above copyright notice, this paragraph
// and the following paragraphs appear in all copies.
// 
// IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY
// PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL
// DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
// 
// THE SOFTWARE PROVIDED HEREIN IS ON AN "AS IS" BASIS, AND THE
// UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO PROVIDE MAINTENANCE,
// SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS. THE UNIVERSITY
// OF CALIFORNIA MAKES NO REPRESENTATIONS AND EXTENDS NO WARRANTIES
// OF ANY KIND, EITHER IMPLIED OR EXPRESS, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A
// PARTICULAR PURPOSE, OR THAT THE USE OF THE SOFTWARE WILL NOT INFRINGE
// ANY PATENT, TRADEMARK OR OTHER RIGHTS.
// 
// The h3.h file is developed by the CoralReef development team at the
// University of California, San Diego under the Cooperative Association
// for Internet Data Analysis (CAIDA) Program.  Support for this effort was
// provided by the CAIDA grant NCR-9711092, DARPA NGI Contract
// N66001-98-2-8922, DARPA NMS Grant N66001-01-1-8909, NSF Grant ANI-013710
// and by CAIDA members.
// 
// Report bugs and suggestions to coral-bugs@caida.org.

// H3 hash function family
// C++ template implementation by Ken Keys (kkeys@caida.org)
//
// Usage:
//    #include <h3.h>
//    const H3<T, N> h;
//    T hashval = h(data, size [, offset]);
// (T) is the type to be returned by the hash function; must be an integral
//     type, e.g. uint32_t.
// (N) is the size of the data in bytes (if data is a struct, beware of
//     padding).
// The hash function hashes the (size) bytes of the data pointed to by (data),
//     starting at (offset).  Note: offset affects the hash value, so
//     h(data, size, offset) is not the same as h(data+offset, size, 0).
//     Typically (size) is N and (offset) is 0, but other values can be used to
//     hash a substring of the data.  Hashes of substrings can be bitwise-XOR'ed
//     together to get the same result as hashing the full string.
// Any number of hash functions can be created by creating new instances of H3,
//     with the same or different template parameters.  The hash function
//     constructor takes a seed as argument which defaults to a call to
//     bro_random().


#ifndef H3_H
#define H3_H

#include <climits>
#include <cstring>

// The number of values representable by a byte.
#define H3_BYTE_RANGE (UCHAR_MAX+1)

template <typename T, int N>
class H3 {
public:
	H3()
		{
		Init(false, 0);
		}

	H3(T seed)
		{
		Init(true, seed);
		}

	void Init(bool have_seed, T seed)
		{
		T bit_lookup[N * CHAR_BIT];

		for ( size_t bit = 0; bit < N * CHAR_BIT; bit++ )
			{
			bit_lookup[bit] = 0;
			for ( size_t i = 0; i < sizeof(T)/2; i++ )
				{
				seed = have_seed ? bro_prng(seed) : bro_random();
				// assume random() returns at least 16 random bits
				bit_lookup[bit] = (bit_lookup[bit] << 16) | (seed & 0xFFFF);
				}
			}

		for ( size_t byte = 0; byte < N; byte++ )
			{
			for ( unsigned val = 0; val < H3_BYTE_RANGE; val++ )
				{
				byte_lookup[byte][val] = 0;
				for ( size_t bit = 0; bit < CHAR_BIT; bit++ )
					// Does this mean byte_lookup[*][0] == 0? -RP
					if (val & (1 << bit))
						byte_lookup[byte][val] ^= bit_lookup[byte*CHAR_BIT+bit];
				}
			}
		}

	T operator()(const void* data, size_t size, size_t offset = 0) const
		{
		const unsigned char *p = static_cast<const unsigned char*>(data);
		T result = 0;

		// loop optmized with Duff's Device
		register unsigned n = (size + 7) / 8;
		switch ( size % 8 ) {
		case 0: do { result ^= byte_lookup[offset++][*p++];
		case 7:      result ^= byte_lookup[offset++][*p++];
		case 6:      result ^= byte_lookup[offset++][*p++];
		case 5:      result ^= byte_lookup[offset++][*p++];
		case 4:      result ^= byte_lookup[offset++][*p++];
		case 3:      result ^= byte_lookup[offset++][*p++];
		case 2:      result ^= byte_lookup[offset++][*p++];
		case 1:      result ^= byte_lookup[offset++][*p++];
				} while ( --n > 0 );
			}

		return result;
		}

	friend bool operator==(const H3& x, const H3& y)
		{
		return ! std::memcmp(x.byte_lookup, y.byte_lookup, N * H3_BYTE_RANGE);
		}

	friend bool operator!=(const H3& x, const H3& y)
		{
		return ! (x == y);
		}

private:
	T byte_lookup[N][H3_BYTE_RANGE];
};

#endif //H3_H
