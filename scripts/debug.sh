#!/bin/sh

set -e

cwd="$(dirname $(realpath $0))"

rm -rf "$cwd/../build"
mkdir -p "$cwd/../build"
cd "$cwd/../build"

export CC=clang
export CXX=clang++

cmake ../ -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX=/usr \
    $@
make -j$(nproc || echo 1)
