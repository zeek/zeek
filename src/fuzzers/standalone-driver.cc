#include <cstdio>
#include <cstdint>
#include <cassert>
#include <memory>
#include <chrono>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);

int main(int argc, char** argv)
	{
	using namespace std::chrono;
	auto agg_start = high_resolution_clock::now();
	auto num_inputs = argc - 1;
	printf("Standalone fuzzer processing %d inputs\n", num_inputs);

	LLVMFuzzerInitialize(&argc, &argv);

	for ( auto i = 0; i < num_inputs; ++i )
		{
		auto input_file_name = argv[i + 1];
		printf("  %s:", input_file_name);

		auto f = fopen(input_file_name, "r");
		assert(f);

		fseek(f, 0, SEEK_END);
		auto input_length = ftell(f);
		fseek(f, 0, SEEK_SET);

		auto input_buffer = std::make_unique<uint8_t[]>(input_length);
		auto bytes_read = fread(input_buffer.get(), 1, input_length, f);
		assert(bytes_read == static_cast<size_t>(input_length));

		auto start = high_resolution_clock::now();
		LLVMFuzzerTestOneInput(input_buffer.get(), input_length);
		auto stop = high_resolution_clock::now();
		auto dt = duration<double>(stop - start).count();

		printf(" %6zu bytes, %f seconds\n", input_length, dt);
		fclose(f);
		}

	auto agg_stop = high_resolution_clock::now();
	auto agg_dt = duration<double>(agg_stop - agg_start).count();
	printf("Processed %d inputs in %fs\n", num_inputs, agg_dt);
}
