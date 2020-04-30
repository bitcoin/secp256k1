#!/bin/sh

./libtool --mode=execute valgrind --error-exitcode=1 ./valgrind_ctime_test "$@"
ret=$?

case $ret in
    127) # "command not found", i.e., either libtool or valgrind not installed
        exit 77 # map this to "SKIP" (=77) for make check
        ;;
    *)
        exit $ret
        ;;
esac
