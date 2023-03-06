# @TEST-DOC: Run ldd on the zeek executable and check that it's linked against libpython

# @TEST-EXEC: ldd $(which zeek) > ldd.out
# @TEST-EXEC: grep libpython ldd.out
