#!/bin/sh

ZEEK_BUILD=""
DATA_FILE=""
MODE="benchmark"

# Path where flamegraph is installed
FLAMEGRAPH_PATH=/usr/local/FlameGraph

usage() {
    usage="\
Usage: $0 -b [zeek binary path] -d [data file path]

  Options:
    -b path        The path to a Zeek binary to benchmark
    -d path        The path to a data file to read from for replay
    -f path        (optional) The path to an SVG file to output a flamegraph
                   for the benchmark run

    By defualt the output will include CPU, memory, etc statistics from Zeek
    processing all of the data in the data file. With the -f argument, the
    script will instead output a flamegraph for the process runtime, showing
    the time spent in functions, etc.
"

    echo "${usage}"
    exit 1
}

while (( "$#" )); do
  case "$1" in
      -d|--data-file)
	  DATA_FILE=$2
	  shift 2
	  ;;
      -b|--build)
	  ZEEK_BUILD=$2
	  shift 2
	  ;;
      -f|--flame-graph)
	  MODE="flamegraph"
	  FG_FILE=$2
	  shift 2
	  ;;
  esac
done

if [ -z $ZEEK_BUILD ]; then
    echo "Error: -b argument is required and should point at a Zeek binary"
    echo
    usage
fi

if [ -z $DATA_FILE ]; then
    echo "Error: -d argument is required and should point at a pcap file to replay"
    echo
    usage
fi

# Various run-time options
INTERFACE="ens1f0"
ZEEK_ARGS="-i af_packet::${INTERFACE}"
ZEEK_CPU=10
TCPREPLAY_CPU=11

echo "Running '${ZEEK_BUILD} ${ZEEK_ARGS}' against ${DATA_FILE}"

if [ "${MODE}" = "benchmark" ]; then

    TIME_FILE=$(mktemp)

    # Start zeek, find it's PID, then wait 10s to let it reach a steady state
    taskset --cpu-list $ZEEK_CPU time -f "%M" -o ${TIME_FILE} $ZEEK_BUILD $ZEEK_ARGS &
    TIME_PID=$!

    sleep 10

    ZEEK_PID=$(ps -ef | awk -v timepid="${TIME_PID}" '{ if ($3 == timepid) { print $2 } }')
    echo "Zeek running on PID ${ZEEK_PID}"

    # Start perf stat on the zeek process
    perf stat -p ${ZEEK_PID} &
    PERF_PID=$!

    # Start replaying the data
    echo "Starting replay"
    taskset --cpu-list $TCPREPLAY_CPU tcpreplay -i $INTERFACE -q $DATA_FILE

    # TODO: does it make sense to sleep here to let zeek finish processing all of the packets
    # out of the kernel buffer?

    # Print the average CPU usage of the process
    echo
    CPU_USAGE=$(ps -p $ZEEK_PID -o %cpu=)

    # Kill everything
    kill -2 $ZEEK_PID
    wait $TIME_PID
    wait $PERF_PID

    echo "Maximum memory usage (max_rss): $(head -n 1 ${TIME_FILE}) bytes"
    echo "Average CPU usage: ${CPU_USAGE}%"

    rm $TIME_FILE

elif [ "${MODE}" = "flamegraph" ]; then

    PERF_RECORD_FILE=$(mktemp)

    # Start zeek under perf record, then sleep for a few seconds to let it actually start up. For runs with
    # shorter amounts of data or with slower traffic, you can add '-c 499' here to get finer-grained results.
    # With big data sets, it just results in the graph getting blown out by waits in the IO loop.
    perf record -g -o $PERF_RECORD_FILE -- $ZEEK_BUILD $ZEEK_ARGS &
    PERF_PID=$!

    sleep 5

    ZEEK_PID=$(ps -ef | awk -v perfpid="${PERF_PID}" '{ if ($3 == perfpid) { print $2 } }')
    echo "Zeek running on PID ${ZEEK_PID}"
    echo

    # Start replaying the data
    echo "Starting replay"
    taskset --cpu-list $TCPREPLAY_CPU tcpreplay -i $INTERFACE -q $DATA_FILE

    # Kill everything
    echo
    kill -2 $ZEEK_PID
    wait $PERF_PID

    echo
    echo "Building SVG for output"
    perf script -i $PERF_RECORD_FILE | ${FLAMEGRAPH_PATH}/stackcollapse-perf.pl | ${FLAMEGRAPH_PATH}/flamegraph.pl > ${FG_FILE}
    rm $PERF_RECORD_FILE

fi
