#!/bin/bash
##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  MIT License                                                               #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  Permission is hereby granted, free of charge, to any person obtaining     #
#  a copy of this software and associated documentation files (the           #
#  "Software"), to deal in the Software without restriction, including       #
#  without limitation the rights to use, copy, modify, merge, publish,       #
#  distribute, sublicense, and/or sell copies of the Software, and to        #
#  permit persons to whom the Software is furnished to do so, subject to     #
#  the following conditions:                                                 #
#                                                                            #
#  The above copyright notice and this permission notice shall be            #
#  included in all copies or substantial portions of the Software.           #
#                                                                            #
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,           #
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF        #
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                     #
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE    #
#  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION    #
#  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION     #
#  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.           #
#                                                                            #
#  automate_cross_gcc_9.sh - Automate library compilation                    #
#                                                                            #
##############################################################################

# $1 -> gcc version
# $2 -> optimization
function do_gcc_x86 {
  if [ ! -d "./builds/x86-gcc-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=gcc-$1
    export CXX=g++-$1
    export CFLAGS="-fno-inline-functions -m32 -O$2  -I/usr/i686-linux-gnu/include/"
    export CXXFLAGS="-fno-inline-functions -m32 -O$2  -I/usr/i686-linux-gnu/include/"
    ./Configure linux-x86
    make clean
    make -j 16
    rm -rf ./builds/x86-gcc-$1-O$2
    mkdir ./builds/x86-gcc-$1-O$2
    cp ./libcrypto.so.3      ./builds/x86-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3         ./builds/x86-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/x86-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/x86-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/x86-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/x86-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/x86-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/x86-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/x86-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/x86-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_x64 {
  if [ ! -d "./builds/x64-gcc-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=gcc-$1
    export CXX=g++-$1
    export CFLAGS="-fno-inline-functions -m64 -O$2"
    export CXXFLAGS="-fno-inline-functions -m64 -O$2"
    ./Configure linux-x86_64
    make clean
    make -j 16
    rm -rf ./builds/x64-gcc-$1-O$2
    mkdir ./builds/x64-gcc-$1-O$2
    cp ./libcrypto.so.3      ./builds/x64-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3         ./builds/x64-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/x64-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/x64-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/x64-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/x64-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/x64-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/x64-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/x64-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/x64-gcc-$1-O$2/legacy.so
  fi
}

# $1 -> clang version
# $2 -> optimization
function do_clang_x86 {
  if [ ! -d "./builds/x86-clang-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=clang-$1
    export CXX=clang++-$1
    export CFLAGS="-fno-inline-functions -m32 -O$2  -I/usr/i686-linux-gnu/include/"
    export CXXFLAGS="-fno-inline-functions -m32 -O$2  -I/usr/i686-linux-gnu/include/"
    ./Configure linux-x86-clang
    make clean
    make -j 16
    rm -rf ./builds/x86-clang-$1-O$2
    mkdir ./builds/x86-clang-$1-O$2
    cp ./libcrypto.so.3      ./builds/x86-clang-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3         ./builds/x86-clang-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/x86-clang-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/x86-clang-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/x86-clang-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/x86-clang-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/x86-clang-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/x86-clang-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/x86-clang-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/x86-clang-$1-O$2/legacy.so
  fi
}

# $1 -> clang version
# $2 -> optimization
function do_clang_x64 {
  if [ ! -d "./builds/x64-clang-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=clang-$1
    export CXX=clang++-$1
    export CFLAGS="-fno-inline-functions -m64 -O$2"
    export CXXFLAGS="-fno-inline-functions -m64 -O$2"
    ./Configure linux-x86_64-clang
    make clean
    make -j 16
    rm -rf ./builds/x64-clang-$1-O$2
    mkdir ./builds/x64-clang-$1-O$2
    cp ./libcrypto.so.3      ./builds/x64-clang-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3         ./builds/x64-clang-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/x64-clang-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/x64-clang-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/x64-clang-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/x64-clang-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/x64-clang-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/x64-clang-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/x64-clang-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/x64-clang-$1-O$2/legacy.so
  fi
}

function do_gcc_arm_32 {
  if [ ! -d "./builds/arm32-gcc-$1-O$2" ]
  then
    export CROSS_COMPILE="arm-linux-gnueabi-"
    export AR=${CROSS_COMPILE}ar
    export AS=${CROSS_COMPILE}as
    export LD=${CROSS_COMPILE}ld
    export RANLIB=${CROSS_COMPILE}ranlib
    export CC=${CROSS_COMPILE}gcc-$1
    export NM=${CROSS_COMPILE}nm
    export CFLAGS="-fno-inline-functions -march=armv8-a -O$2"
    export CXX=${CROSS_COMPILE}g++-$1
    export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2"
    unset CROSS_COMPILE
    ./Configure linux-armv4
    make clean
    make -j 16
    rm -rf ./builds/arm32-gcc-$1-O$2
    mkdir ./builds/arm32-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/arm32-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/arm32-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/arm32-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/arm32-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/arm32-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/arm32-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/arm32-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/arm32-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/arm32-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/arm32-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_arm_48_32 {
  if [ ! -d "./builds/arm32-gcc-$1-O$2" ]
  then
    #export CROSS_COMPILE="arm-linux-gnueabi-"
    export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ar
    export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-as
    export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ld
    export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ranlib
    export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-gcc
    export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-nm
    export CFLAGS="-fno-inline-functions -march=armv8-a -O$2"
    export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-g++
    export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2"
    ./Configure linux-armv4
    make clean
    make -j 16
    rm -rf ./builds/arm32-gcc-$1-O$2
    mkdir ./builds/arm32-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/arm32-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/arm32-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/arm32-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/arm32-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/arm32-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/arm32-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/arm32-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/arm32-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/arm32-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/arm32-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_arm_64 {
  if [ ! -d "./builds/arm64-gcc-$1-O$2" ]
  then
    export CROSS_COMPILE="aarch64-linux-gnu-"
    export AR=${CROSS_COMPILE}ar
    export AS=${CROSS_COMPILE}as
    export LD=${CROSS_COMPILE}ld
    export RANLIB=${CROSS_COMPILE}ranlib
    export CC=${CROSS_COMPILE}gcc-$1
    export NM=${CROSS_COMPILE}nm
    export CFLAGS="-fno-inline-functions -march=armv8-a -O$2"
    export CXX=${CROSS_COMPILE}g++-$1
    export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2"
    unset CROSS_COMPILE
    ./Configure linux-aarch64
    make clean
    make -j 16
    rm -rf ./builds/arm64-gcc-$1-O$2
    mkdir ./builds/arm64-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/arm64-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/arm64-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/arm64-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/arm64-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/arm64-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/arm64-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/arm64-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/arm64-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/arm64-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/arm64-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_mips_32 {
  if [ ! -d "./builds/mips32-gcc-$1-O$2" ]
  then
    export CROSS_COMPILE="mips-linux-gnu-"
    export AR=${CROSS_COMPILE}ar
    export AS=${CROSS_COMPILE}as
    export LD=${CROSS_COMPILE}ld
    export RANLIB=${CROSS_COMPILE}ranlib
    export CC=${CROSS_COMPILE}gcc-$1
    export NM=${CROSS_COMPILE}nm
    export CFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
    export CXX=${CROSS_COMPILE}g++-$1
    export CXXFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
    unset CROSS_COMPILE
    ./Configure linux-mips32
    make clean
    make -j 16
    rm -rf ./builds/mips32-gcc-$1-O$2
    mkdir ./builds/mips32-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips32-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips32-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips32-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips32-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips32-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips32-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips32-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips32-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips32-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips32-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_mips_48_32 {
  if [ ! -d "./builds/mips32-gcc-$1-O$2" ]
  then
    #export CROSS_COMPILE="mips-linux-gnu-"
    export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ar
    export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-as
    export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ld
    export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ranlib
    export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-gcc
    export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-nm
    export CFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
    export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-g++
    export CXXFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
    ./Configure linux-mips32
    make clean
    make -j 16
    rm -rf ./builds/mips32-gcc-$1-O$2
    mkdir ./builds/mips32-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips32-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips32-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips32-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips32-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips32-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips32-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips32-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips32-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips32-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips32-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_mips_64 {
  if [ ! -d "./builds/mips64-gcc-$1-O$2" ]
  then
    export CROSS_COMPILE="mips64-linux-gnuabi64"
    export AR=${CROSS_COMPILE}-ar
    export AS=${CROSS_COMPILE}-as
    export LD=${CROSS_COMPILE}-ld
    export RANLIB=${CROSS_COMPILE}-ranlib
    export CC=${CROSS_COMPILE}-gcc-$1
    export NM=${CROSS_COMPILE}-nm
    export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
    export CXX=${CROSS_COMPILE}-g++-$1
    export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
    unset CROSS_COMPILE
    ./Configure linux64-mips64
    make clean
    make -j 16
    rm -rf ./builds/mips64-gcc-$1-O$2
    mkdir ./builds/mips64-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips64-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips64-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips64-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips64-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips64-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips64-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips64-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips64-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips64-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips64-gcc-$1-O$2/legacy.so
  fi
}

function do_gcc_mips_48_64 {
  if [ ! -d "./builds/mips64-gcc-$1-O$2" ]
  then
    #export CROSS_COMPILE="mips64-linux-gnu"
    export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ar
    export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-as
    export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ld
    export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ranlib
    export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-gcc
    export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-nm
    export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
    export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-g++
    export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
    ./Configure linux64-mips64
    make clean
    make -j 16
    rm -rf ./builds/mips64-gcc-$1-O$2
    mkdir ./builds/mips64-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips64-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips64-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips64-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips64-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips64-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips64-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips64-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips64-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips64-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips64-gcc-$1-O$2/legacy.so
  fi
}

function do_clang_arm_32 {
  if [ ! -d "./builds/arm32-clang-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=clang-$1
    export CXX=clang++-$1
    export CFLAGS="-fno-inline-functions --target=arm-linux-gnu -march=armv8 -mfloat-abi=soft --sysroot=/usr/arm-linux-gnueabi -O$2  -Wl,-z,notext -I/usr/arm-linux-gnueabi/include/c++/7/ -I/usr/arm-linux-gnueabi/include/c++/7/arm-linux-gnueabi/"
    export CXXFLAGS="-fno-inline-functions --target=arm-linux-gnu -march=armv8 -mfloat-abi=soft --sysroot=/usr/arm-linux-gnueabi -O$2 -Wl,-z,notext -I/usr/arm-linux-gnueabi/include/c++/7/ -I/usr/arm-linux-gnueabi/include/c++/7/arm-linux-gnueabi/"
    export LDFLAGS="-fuse-ld=lld-8 --target=arm-linux-gnu --sysroot=/usr/arm-linux-gnueabi -L/usr/arm-linux-gnueabi/lib"
    ./Configure linux-generic32
    make clean
    make -j 16
    rm -rf ./builds/arm32-clang-$1-O$2
    mkdir ./builds/arm32-clang-$1-O$2
    cp ./libcrypto.so.3 ./builds/arm32-clang-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/arm32-clang-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/arm32-clang-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/arm32-clang-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/arm32-clang-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/arm32-clang-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/arm32-clang-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/arm32-clang-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/arm32-clang-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/arm32-clang-$1-O$2/legacy.so
  fi
}

function do_clang_arm_64 {
  if [ ! -d "./builds/arm64-clang-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=clang-$1
    export CXX=clang++-$1
    # -march=armv8-a seems to give problems, we can remove it as aarch64 is armv8 already
    export CFLAGS="-fno-inline-functions --target=aarch64-linux-gnu -mfloat-abi=soft --sysroot=/usr/aarch64-linux-gnu -O$2  -Wl,-z,notext -I/usr/aarch64-linux-gnu/include/c++/7/ -I/usr/aarch64-linux-gnu/include/c++/7/aarch64-linux-gnu/"
    export CXXFLAGS="-fno-inline-functions --target=aarch64-linux-gnu -mfloat-abi=soft --sysroot=/usr/aarch64-linux-gnu -O$2  -Wl,-z,notext -I/usr/aarch64-linux-gnu/include/c++/7/ -I/usr/aarch64-linux-gnu/include/c++/7/aarch64-linux-gnu/"
    export LDFLAGS="-fuse-ld=lld-8  --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu -L/usr/aarch64-linux-gnu/lib"

    ./Configure linux-aarch64
    make clean
    make -j 16
    rm -rf ./builds/arm64-clang-$1-O$2
    mkdir ./builds/arm64-clang-$1-O$2
    cp ./libcrypto.so.3 ./builds/arm64-clang-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/arm64-clang-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/arm64-clang-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/arm64-clang-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/arm64-clang-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/arm64-clang-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/arm64-clang-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/arm64-clang-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/arm64-clang-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/arm64-clang-$1-O$2/legacy.so
  fi
}

function do_clang_mips_32 {
  if [ ! -d "./builds/mips32-clang-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=clang-$1
    export CXX=clang++-$1
    export CFLAGS="-fno-integrated-as -fno-inline-functions --target=mips-linux-gnu -march=mips32r2 --sysroot=/usr/mips-linux-gnu -O$2 -Wl,-z,notext  -Wl,-z,notext -I/usr/mips-linux-gnu/include/c++/7/mips-linux-gnu/ -I/usr/mips-linux-gnu/include/c++/7/"
    export CXXFLAGS="-fno-integrated-as -fno-inline-functions  --target=mips-linux-gnu -march=mips32r2 --sysroot=/usr/mips-linux-gnu -O$2 -Wl,-z,notext  -Wl,-z,notext -I/usr/mips-linux-gnu/include/c++/7/mips-linux-gnu/ -I/usr/mips-linux-gnu/include/c++/7/"
    export LDFLAGS="-fuse-ld=lld-8 --target=mips-linux-gnu --sysroot=/usr/mips-linux-gnu -L/usr/mips-linux-gnu/lib"

    ./Configure linux-mips32
    make clean
    make -j 16
    rm -rf ./builds/mips32-clang-$1-O$2
    mkdir ./builds/mips32-clang-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips32-clang-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips32-clang-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips32-clang-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips32-clang-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips32-clang-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips32-clang-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips32-clang-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips32-clang-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips32-clang-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips32-clang-$1-O$2/legacy.so
  fi
}

function do_clang_mips_64 {
  if [ ! -d "./builds/mips64-clang-$1-O$2" ]
  then
    unset CROSS_COMPILE
    unset AS
    unset LD
    unset AR
    unset RANLIB
    unset NM
    export CC=clang-$1
    export CXX=clang++-$1
    # -mfloat-abi=soft
    export CFLAGS="-fno-integrated-as -fno-inline-functions  --target=mips64-linux-gnuabi64 -march=mips64r2 -mabi=64 --sysroot=/usr/mips64-linux-gnuabi64 -O$2  -Wl,-z,notext -I/usr/mips64-linux-gnuabi64/include/c++/7/mips64-linux-gnuabi64 -I/usr/mips64-linux-gnuabi64/include/c++/7/"
    export CXXFLAGS="-fno-integrated-as -fno-inline-functions  --target=mips64-linux-gnuabi64 -march=mips64r2 -mabi=64 --sysroot=/usr/mips64-linux-gnuabi64 -O$2  -Wl,-z,notext -I/usr/mips64-linux-gnuabi64/include/c++/7/mips64-linux-gnuabi64 -I/usr/mips64-linux-gnuabi64/include/c++/7/"
    export LDFLAGS="-fuse-ld=lld-8 --target=mips64-linux-gnuabi64 --sysroot=/usr/mips64-linux-gnuabi64 -L/usr/mips64-linux-gnuabi64/lib"

    ./Configure linux64-mips64
    make clean
    make -j 16 
    rm -rf ./builds/mips64-clang-$1-O$2
    mkdir ./builds/mips64-clang-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips64-clang-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips64-clang-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips64-clang-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips64-clang-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips64-clang-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips64-clang-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips64-clang-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips64-clang-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips64-clang-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips64-clang-$1-O$2/legacy.so
  fi
}

function do_gcc_mips_9_64 {
  if [ ! -d "./builds/mips64-gcc-$1-O$2" ]
  then
    #export CROSS_COMPILE="mips64-linux-gnu"
    export AR=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ar
    export AS=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-as
    export LD=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ld
    export RANLIB=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ranlib
    export CC=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-gcc
    export NM=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-nm
    export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
    export CXX=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-g++
    export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
    ./Configure linux64-mips64
    make clean
    make -j 16
    rm -rf ./builds/mips64-gcc-$1-O$2
    mkdir ./builds/mips64-gcc-$1-O$2
    cp ./libcrypto.so.3 ./builds/mips64-gcc-$1-O$2/libcrypto.so.3
    cp ./libssl.so.3 ./builds/mips64-gcc-$1-O$2/libssl.so.3
    cp ./apps/openssl        ./builds/mips64-gcc-$1-O$2/openssl
    cp ./engines/afalg.so    ./builds/mips64-gcc-$1-O$2/afalg.so
    cp ./engines/capi.so     ./builds/mips64-gcc-$1-O$2/capi.so
    cp ./engines/dasync.so   ./builds/mips64-gcc-$1-O$2/dasync.so
    cp ./engines/ossltest.so ./builds/mips64-gcc-$1-O$2/ossltest.so
    cp ./engines/padlock.so  ./builds/mips64-gcc-$1-O$2/padlock.so
    cp ./providers/fips.so   ./builds/mips64-gcc-$1-O$2/fips.so
    cp ./providers/legacy.so ./builds/mips64-gcc-$1-O$2/legacy.so
  fi
}

# GCC MIPS64 // 9 must be done on 19.10 / 4.8 must be done differently 
for gcc_v in 9
do
    for opt_level in 0 1 2 3 s
    do
        do_gcc_mips_9_64 $gcc_v $opt_level
    done
done

# GCC MIPS32 // 9 must be done on 19.10 / 4.8 must be done differently 
for gcc_v in 9
do
    for opt_level in 0 1 2 3 s
    do
        do_gcc_mips_32 $gcc_v $opt_level
    done
done

# GCC ARM32 // 9 must be done on 19.10, 4.8 must be done differently 
for gcc_v in 9
do
    for opt_level in 0 1 2 3 s
    do
        do_gcc_arm_32 $gcc_v $opt_level
    done
done

# GCC ARM64 // 9 must be done on 19.10 
for gcc_v in 9
do
    for opt_level in 0 1 2 3 s
    do
        do_gcc_arm_64 $gcc_v $opt_level
    done
done

