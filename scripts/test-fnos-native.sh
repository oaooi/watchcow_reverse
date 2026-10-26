#!/bin/bash
# Run a native fnOS Nginx integration test without changing the live NAS.
set -euo pipefail
test_dir=$(realpath "${1:?usage: test-fnos-native.sh /root/.work/TASK/native-test}")
case "$test_dir" in /root/.work/*) ;; *) echo "Use a task directory below /root/.work" >&2; exit 1 ;; esac
test -x "$test_dir/reverse.test"
test ! -e "$test_dir/nginx-prefix"
mkdir "$test_dir/nginx-prefix"
cp -a /usr/trim/nginx/conf /usr/trim/nginx/sbin /usr/trim/nginx/modules "$test_dir/nginx-prefix/"
mkdir "$test_dir/nginx-prefix/logs"
export WATCHCOW_R_NATIVE_TEST=1 WATCHCOW_R_NATIVE_DIR="$test_dir"
export WATCHCOW_R_HOST_mnt=$(readlink /proc/self/ns/mnt)
export WATCHCOW_R_HOST_net=$(readlink /proc/self/ns/net)
export WATCHCOW_R_HOST_pid=$(readlink /proc/self/ns/pid)
exec unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private bash -euc '
    mount --bind "$WATCHCOW_R_NATIVE_DIR/nginx-prefix" /usr/trim/nginx
    mount -t tmpfs tmpfs /run
    mount -t tmpfs tmpfs /usr/trim/www
    ip link set lo up
    exec "$WATCHCOW_R_NATIVE_DIR/reverse.test" -test.run "^TestNativeNginxEndToEnd$" -test.v
'
