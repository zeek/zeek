# zeek-archiver

A Zeek log archival service.

This tool is derived from
[bro-atomic-rotate](https://github.com/ncsa/bro-atomic-rotate)
and intends to solve two failings of Zeek's historical log-archival
process: robustness and atomicity.  It's rewritten with two further
requirements in mind:

* Independence from [ZeekControl](https://github.com/zeek/zeekctl).
  It's meant for use in conjunction with the upcoming
  [Zeek Supervisor Framework](https://docs.zeek.org/en/current/frameworks/supervisor.html).
* Independence from Python.  In retrospect, it's dubious whether that's
  a benefit: implementing in C++ has little advantage over a solution done in
  a simpler Bash/Python script, so it may get completely rewritten
  later if any concrete maintenance burden/problems are encountered.

## Dependencies

* CMake 3.0 or greater
* C++ compiler with C++17 support (GCC 7+ or Clang 4+)
* By default, compression is enabled by shelling out directly to `gzip`,
  either install that separately or disable/change the compression
  mechanism via the `--compression=` flag.

## Installation

Since `zeek-archiver` is made for use with the Zeek Supervisor Framework,
you should first install Zeek and configure your Supervised Cluster, based
on the example given here which will rotate logs into `$(cwd)/logger/log-queue/`:
https://docs.zeek.org/en/current/frameworks/supervisor.html#supervised-cluster-example

After, install/configure `zeek-archiver` itself as a service:

```
$ make install
$ cp zeek-archiver.service /etc/systemd/system/
# Modify the ExecStart invocation in service file as needed.
$ systemctl enable zeek-archiver
$ systemctl start zeek-archiver
```

## Use With ZeekControl

While `zeek-archiver` is meant to be used with the Zeek Supervisor Framework,
it's still possible to use with ZeekControl in the time before it's entirely
succeeded by the Supervisor Framework.  As an example of how to configure
`zeek-archiver` to work with ZeekControl, add this code to your `local.zeek`

```zeek
@if ( Cluster::local_node_type() == Cluster::LOGGER )

redef Log::default_rotation_dir = "/usr/local/zeek/logs/log-queue";

function my_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$close);
	local base = fmt("%s__%s__%s__", ri$path, open_str, close_str);
	local rval = Log::RotationPath($file_basename=base);
	return rval;
	}

redef Log::rotation_format_func = my_rotation_format_func;
redef Log::default_rotation_postprocessor_cmd = "";

@endif
```

Then run `zeek-archiver` the same way as explained earlier to have it monitor
and rotate any logs that show up in `/usr/local/zeek/logs/log-queue`.

## Further Background

The historical ZeekControl method for log rotation/archival looked like:

```
mv conn.log conn-yaddayadda.log
gzip < conn-yaddayadda.log > /bro/logs/2018/10/10/conn.09:00:00-10:00:00.gz
```

But that is not an "atomic" operation that's robust in the face of power less,
reboot, OOM, something trying to read `.gz` files as they're created.
The archival process for each log also happened all concurrently with one
another, which creates problematic load spikes.

Instead, `zeek-archiver` archives log files serially and atomically in a way
that depends on which criteria is met:

* If compression is desired: `gzip < src > dst.tmp && mv dst.tmp dst && rm src`
* No compression, within same filesystem: `mv src dst`
* No compression, across filesystems: `cp src dst.tmp && mv dst.tmp dst && rm src`
