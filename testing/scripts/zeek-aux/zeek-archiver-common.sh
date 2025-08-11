# Common functionality for zeek-archiver's tests, originally found in its own
# test.sh script that wasn't using btest.

set -e
set -x

function queue_dir {
    mkdir -p queue
    echo queue
}

function archive_dir {
    echo archive
}

function archive_date_dir {
    echo archive/2020-07-16
}
