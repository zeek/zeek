# Compressed and pcapng output

Details for the rare traces that need gzip compression or the pcapng format.
The default remains a plain, uncompressed `<name>.pcap` (see `SKILL.md`).

## gzip

- gzip is only worth it for large, highly compressible traces (repetitive
  payloads, e.g. resource-exhaustion reproducers that shrink by 50x+). For a
  normal small trace, leave it uncompressed; a plain pcap is nicer to inspect
  and diff.
- Write through `gzip.GzipFile(path, "wb", mtime=0)` and pass that handle to
  `wrpcap(f, packets)`. `mtime=0` is what makes the bytes reproducible; do NOT
  use `wrpcap(..., gz=1)`, which embeds a build-time mtime. The output is then
  `<name>.pcap.gz`:
  `gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0)`.
  `with_suffix(".gz")` replaces only the `.py` and yields `<name>.pcap.gz`.
  (Do NOT use `with_suffix(".pcap.gz")` — that would produce
  `<name>.pcap.pcap.gz`.)

## pcapng

- Use pcapng only when absolutely necessary. Plain pcap also records a capture
  length below the wire length (set `p.wirelen`). As an exception to the naming
  rule, name the script `<name>.pcapng.py` and write with `wrpcapng(...)`;
  `with_suffix("")` still strips only `.py` and yields `<name>.pcapng`.
- Gzipping a pcapng needs a workaround: unlike `wrpcap()`, `wrpcapng()` only
  accepts a path (not a file handle) in Scapy 2.7.0, so you cannot pass it a
  `gzip.GzipFile`. Write a plain pcapng to a temp file beside the final output,
  then gzip that:

  ```python
  # wrpcapng() only accepts a path in Scapy 2.7.0, so gzip a plain file.
  final = Path(__file__).with_suffix(".gz")
  with tempfile.NamedTemporaryFile(dir=final.parent, suffix=".pcapng") as tmp:
      wrpcapng(tmp.name, packets)
      with gzip.GzipFile(final, "wb", mtime=0) as gz:
          shutil.copyfileobj(tmp, gz)
  ```

  (`dir=final.parent` keeps the temp file on the same filesystem; `mtime=0`
  still makes the gzip bytes reproducible.)
