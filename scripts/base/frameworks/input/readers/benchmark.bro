##! Interface for the benchmark input reader.

module InputBenchmark;

export {
	## Multiplication factor for each second.
	const factor = 1.0 &redef;

	## Spread factor between lines.
	const spread = 0 &redef;

	## Spreading where usleep = 1000000 / autospread * num_lines
	const autospread = 0.0 &redef;

	## Addition factor for each heartbeat.
	const addfactor = 0 &redef;

	## Stop spreading at x lines per heartbeat.
	const stopspreadat = 0 &redef;

	## 1 -> enable timed spreading.
	const timedspread = 0.0 &redef;
}
