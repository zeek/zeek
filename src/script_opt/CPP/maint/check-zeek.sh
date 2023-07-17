#! /bin/sh

/bin/echo -n $1" "
(src/zeek --parse-only $1 >/dev/null 2>&1 && echo "success") || echo "fail"
