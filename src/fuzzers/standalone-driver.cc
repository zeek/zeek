#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "zeek/zeek-setup.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);

int main(int argc, char** argv)
	{
	using namespace std::chrono;
	auto agg_start = high_resolution_clock::now();
	auto num_inputs = argc - 1;
	printf("Standalone fuzzer processing %d inputs\n", num_inputs);

	LLVMFuzzerInitialize(&argc, &argv);
	auto fuzz_start = high_resolution_clock::now();

	for ( auto i = 0; i < num_inputs; ++i )
		{
		auto input_file_name = argv[i + 1];
		printf("  %s:", input_file_name);
		// If ASan ends up aborting, the previous stdout output may not
		// be flushed, so make sure to that and make it easier to see
		// what input caused the crash.
		fflush(stdout);

		auto f = fopen(input_file_name, "r");

		if ( ! f )
			{
			printf(" failed to open file: %s\n", strerror(errno));
			abort();
			}

		fseek(f, 0, SEEK_END);
		auto input_length = ftell(f);
		fseek(f, 0, SEEK_SET);

		auto input_buffer = std::make_unique<uint8_t[]>(input_length);
		auto bytes_read = fread(input_buffer.get(), 1, input_length, f);

		if ( bytes_read != static_cast<size_t>(input_length) )
			{
			printf(" failed to read full file: %zu/%ld\n", bytes_read, input_length);
			abort();
			}

		auto start = high_resolution_clock::now();
		LLVMFuzzerTestOneInput(input_buffer.get(), input_length);
		auto stop = high_resolution_clock::now();
		auto dt = duration<double>(stop - start).count();

		printf(" %6zu bytes, %f seconds\n", input_length, dt);
		fclose(f);
		}

	auto agg_stop = high_resolution_clock::now();
	auto agg_dt = duration<double>(agg_stop - agg_start).count();
	auto fuzz_dt = duration<double>(agg_stop - fuzz_start).count();
	printf("Processed %d inputs in %fs (%fs w/ initialization), avg = %fs\n", num_inputs, fuzz_dt,
	       agg_dt, fuzz_dt / num_inputs);
	return zeek::detail::cleanup(false);
	}
