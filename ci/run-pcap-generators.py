#!/usr/bin/env python3
"""
Run all PCAP generators in testing/btest/Traces using runpy.run_path().

Scapy takes like half a second to import, so running everything with runpy
allows to re-use the import and speed this up significantly.

Generators in contentline/ can be skipped with --skip-slow. Haven't looked
too closely, but they each take >5s and so they each take 5x more time than
all remaining generators together. Should probably be rewritten.
"""

import argparse
import contextlib
import dataclasses
import hashlib
import importlib
import itertools
import logging
import pathlib
import runpy
import sys
import time


@dataclasses.dataclass
class GeneratorResult:
    duration: float


@contextlib.contextmanager
def patch_sys_argv(argv):
    orig_sys_argv = sys.argv
    try:
        sys.argv = argv
        yield
    finally:
        sys.argv = orig_sys_argv


@contextlib.contextmanager
def timeit():
    @dataclasses.dataclass
    class _TimeitResult:
        duration: float

    result = _TimeitResult(0.0)

    start_time = time.time()
    try:
        yield result
    finally:
        end_time = time.time()
        result.duration = end_time - start_time


def main():
    zeek_dir = pathlib.Path(__file__).parent.parent
    default_traces_dir = zeek_dir / "testing" / "btest" / "Traces"

    parser = argparse.ArgumentParser()
    parser.add_argument("--traces-dir", default=default_traces_dir, type=pathlib.Path)
    parser.add_argument("--skip-slow", action="store_true", default=False)
    parser.add_argument("--show-slow", default=10, type=int)
    parser.add_argument("--warn-slow", default=1.0, type=float)
    parser.add_argument("--quiet", action="store_true", default=False)
    args = parser.parse_args()

    # Pre-import scapy and scapy.all so that the generators do not need to.
    with timeit() as import_timer:
        scapy_mod = importlib.import_module("scapy")
        _ = importlib.import_module("scapy.all")

    if not args.quiet:
        print(
            f"Scapy version {scapy_mod.__version__} (import took {import_timer.duration:.3f} seconds)"
        )

    generator_results = {}

    for generator in sorted(
        itertools.chain(
            args.traces_dir.rglob("*.pcap.py"), args.traces_dir.rglob("*.pcapng.py")
        )
    ):
        generator_rel = str(generator.relative_to(args.traces_dir))

        # The ones in contentline/ are very very very slow because
        # they produce a lot of data apparently (?).
        #
        # Maybe: Could also consider a SLOW = True per module variable
        # or some such, but preferably we'd just make them all fast.
        if args.skip_slow and generator_rel.startswith("contentline/"):
            if not args.quiet:
                print("s", end="", flush=True)
            continue

        # Wonder if we should have pcap.gz.py / pcapng.gz.py as convention,
        # instead of "maybe gz compressed, who knows".
        pcap = generator.with_suffix("")
        pcap_gz = generator.with_suffix(".gz")

        if not (pcap.is_file() or pcap_gz.is_file()):
            logging.error("neither %s nor %s exist!", pcap, pcap_gz)
            sys.exit(1)
        elif pcap.is_file() and pcap_gz.is_file():
            logging.error("%s and %s exist!", pcap, pcap_gz)
            sys.exit(1)

        pcap_actual = pcap if pcap.is_file() else pcap_gz
        tmp_pcap = pcap_actual.with_suffix(pcap_actual.suffix + ".bak")

        digest = hashlib.sha256(pcap_actual.read_bytes()).hexdigest()

        try:
            pcap_actual.rename(tmp_pcap)

            with patch_sys_argv([str(generator)]):
                with timeit() as timer:
                    runpy.run_path(str(generator), run_name="__main__")

                if not args.quiet:
                    print(".", end="", flush=True)

            # --quiet is ignored for --warn-slow
            if timer.duration > args.warn_slow:
                logging.warning("%s: took %.3f seconds", generator_rel, timer.duration)

            generator_results[generator_rel] = GeneratorResult(timer.duration)

            if not pcap_actual.is_file():
                logging.error("%s: did not create %s", generator_rel, pcap_actual)
                sys.exit(1)

            digest_new = hashlib.sha256(pcap_actual.read_bytes()).hexdigest()

            if digest != digest_new:
                logging.error("%s: hash of %s changed!", generator_rel, pcap_actual)
                sys.exit(1)

        except SystemExit:
            logging.error("%s: raised SystemExit!", generator_rel)
            sys.exit(1)
        except Exception:
            logging.exception("%s: caused an exception!", generator_rel)
            raise
        finally:
            # Restore the file if no other was created...
            if not pcap_actual.is_file():
                tmp_pcap.rename(pcap_actual)
            else:
                tmp_pcap.unlink()

    if not args.quiet:
        print("")

    if not args.quiet and args.show_slow > 0:
        by_duration = sorted(generator_results.items(), key=lambda kv: -kv[1].duration)
        print(f"{'slowest generators (' + str(args.show_slow) + ')':60s} seconds")
        for generator_rel, result in by_duration[: args.show_slow]:
            print(f"{generator_rel:60s} {result.duration:.3f}")


if __name__ == "__main__":
    main()
