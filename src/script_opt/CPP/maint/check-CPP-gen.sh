#! /bin/sh

out=out.`echo $1 | sed 's,\.\./,,;s,/,#,g'`

(/bin/echo -n $1" "
(src/zeek -O gen-C++ --optimize-files=testing/btest --optimize-func="<global-stmts>" $1 >& /dev/null && echo "success") || echo "fail") >CPP-test/$out 2>&1
