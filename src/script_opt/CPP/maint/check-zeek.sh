#! /bin/sh

/bin/echo -n $1" "
(src/zeek --parse-only $1 >&/dev/null && echo "success") || echo "fail"
