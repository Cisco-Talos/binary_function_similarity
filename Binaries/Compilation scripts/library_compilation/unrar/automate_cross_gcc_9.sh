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
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CC=gcc-$1
  export CXX=g++-$1
  export CFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/"
  export CXXFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/"
  export LDFLAGS="-pthread -fno-inline-functions -m32 -O$2 -Wl,-z,notext -I/usr/i686-linux-gnu/include/"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/x86-gcc-$1-O$2
  mkdir ./builds/x86-gcc-$1-O$2
  cp ./unrar    ./builds/x86-gcc-$1-O$2/unrar
}

function do_gcc_x64 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CC=gcc-$1
  export CXX=g++-$1
  export CFLAGS="-fno-inline-functions -m64 -O$2"
  export CXXFLAGS="-fno-inline-functions -m64 -O$2"
  export LDFLAGS="-pthread -fno-inline-functions -m64 -O$2 -Wl,-z,notext"
  export LIBS="-libverbs"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make


  rm -rf ./builds/x64-gcc-$1-O$2
  mkdir ./builds/x64-gcc-$1-O$2
  cp ./unrar    ./builds/x64-gcc-$1-O$2/unrar
}

# $1 -> clang version
# $2 -> optimization
function do_clang_x86 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CC=clang-$1
  export CXX=clang++-$1
  export CFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/"
  export CXXFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/"
  export LDFLAGS="-pthread -fno-inline-functions -m32 -O$2 -Wl,-z,notext -I/usr/i686-linux-gnu/include/"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/x86-clang-$1-O$2
  mkdir ./builds/x86-clang-$1-O$2
  cp ./unrar    ./builds/x86-clang-$1-O$2/unrar
}

# $1 -> clang version
# $2 -> optimization
function do_clang_x64 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CC=clang-$1
  export CXX=clang++-$1
  export CFLAGS="-fno-inline-functions -m64 -O$2"
  export CXXFLAGS="-fno-inline-functions -m64 -O$2"
  export LDFLAGS="-pthread -fno-inline-functions -m64 -O$2 -Wl,-z,notext"
  export LIBS="-libverbs"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/x64-clang-$1-O$2
  mkdir ./builds/x64-clang-$1-O$2
  cp ./unrar    ./builds/x64-clang-$1-O$2/unrar
}

function do_gcc_arm_32 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="arm-linux-gnueabi"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=armv8-a -O$2"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/arm32-gcc-$1-O$2
  mkdir ./builds/arm32-gcc-$1-O$2
  cp ./unrar    ./builds/arm32-gcc-$1-O$2/unrar
}

function do_gcc_arm_48_32 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="arm-linux-gnueabi"
  export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ar
  export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-as
  export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ld
  export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ranlib
  export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-gcc
  export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-nm
  export CFLAGS="-fno-inline-functions -march=armv8-a -O$2"
  export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-g++
  export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/arm32-gcc-$1-O$2
  mkdir ./builds/arm32-gcc-$1-O$2
  cp ./unrar    ./builds/arm32-gcc-$1-O$2/unrar
}

function do_gcc_arm_64 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="aarch64-linux-gnu"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=armv8-a -O$2"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/arm64-gcc-$1-O$2
  mkdir ./builds/arm64-gcc-$1-O$2
  cp ./unrar   ./builds/arm64-gcc-$1-O$2/unrar
}

function do_gcc_mips_32 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips-linux-gnu"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips32-gcc-$1-O$2
  mkdir ./builds/mips32-gcc-$1-O$2
  cp ./unrar    ./builds/mips32-gcc-$1-O$2/unrar
}

function do_gcc_mips_48_32 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips-linux-gnu"
  export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ar
  export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-as
  export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ld
  export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ranlib
  export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-gcc
  export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-nm
  export CFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
  export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-g++
  export CXXFLAGS="-fno-inline-functions -march=mips32r2 -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips32-gcc-$1-O$2
  mkdir ./builds/mips32-gcc-$1-O$2
  cp ./unrar    ./builds/mips32-gcc-$1-O$2/unrar
}

function do_gcc_mips_64 {
  unset LIBS
  unset LDFLAGS
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
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips64-gcc-$1-O$2
  mkdir ./builds/mips64-gcc-$1-O$2
  cp ./unrar    ./builds/mips64-gcc-$1-O$2/unrar
}

function do_gcc_mips_48_64 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips64-linux-gnu"
  export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ar
  export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-as
  export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ld
  export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ranlib
  export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-gcc
  export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-nm
  export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
  export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-g++
  export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips64-gcc-$1-O$2
  mkdir ./builds/mips64-gcc-$1-O$2
  cp ./unrar    ./builds/mips64-gcc-$1-O$2/unrar
}

function do_clang_arm_32 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="arm-linux-gnueabi"
  export CC=clang-$1
  export CXX=clang++-$1
  export CFLAGS="-fno-inline-functions -fuse-ld=lld --target=arm-linux-gnu -march=armv8 -mfloat-abi=soft --sysroot=/usr/arm-linux-gnueabi -O$2 -Wl,-z,notext -I/usr/arm-linux-gnueabi/include/c++/7/ -I/usr/arm-linux-gnueabi/include/c++/7/arm-linux-gnueabi/"
  export CXXFLAGS="-fno-inline-functions -fuse-ld=lld --target=arm-linux-gnu -march=armv8 -mfloat-abi=soft --sysroot=/usr/arm-linux-gnueabi -O$2 -Wl,-z,notext -I/usr/arm-linux-gnueabi/include/c++/7/ -I/usr/arm-linux-gnueabi/include/c++/7/arm-linux-gnueabi/"
  # Due to the following error, -Wl,-z,notext needs to be added
  # ld.lld: error: can't create dynamic relocation R_MIPS_32 against local symbol in readonly segment; recompile object files with -fPIC or pass '-Wl,-z,notext' to allow text relocations in the output
  export LDFLAGS="-pthread -fuse-ld=lld --target=arm-linux-gnu --sysroot=/usr/arm-linux-gnueabi -L/usr/arm-linux-gnueabi/lib"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/arm32-clang-$1-O$2
  mkdir ./builds/arm32-clang-$1-O$2
  cp ./unrar    ./builds/arm32-clang-$1-O$2/unrar
}

function do_clang_arm_64 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="aarch64-linux-gnu"
  export CC=clang-$1
  export CXX=clang++-$1
  # -march=armv8 we remove armv8, not detected, and aarch64 is armv8 in any case
  export CFLAGS="-fno-inline-functions -fuse-ld=lld --target=aarch64-linux-gnu  -mfloat-abi=soft --sysroot=/usr/aarch64-linux-gnu -O$2 -Wl,-z,notext -I/usr/aarch64-linux-gnu/include/c++/7/ -I/usr/aarch64-linux-gnu/include/c++/7/aarch64-linux-gnu/"
  export CXXFLAGS="-fno-inline-functions -fuse-ld=lld --target=aarch64-linux-gnu  -mfloat-abi=soft --sysroot=/usr/aarch64-linux-gnu -O$2 -Wl,-z,notext -I/usr/aarch64-linux-gnu/include/c++/7/ -I/usr/aarch64-linux-gnu/include/c++/7/aarch64-linux-gnu/"
  # Due to the following error, -Wl,-z,notext needs to be added
  # ld.lld: error: can't create dynamic relocation R_MIPS_32 against local symbol in readonly segment; recompile object files with -fPIC or pass '-Wl,-z,notext' to allow text relocations in the output
  export LDFLAGS="-pthread -fuse-ld=lld --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/arm64-clang-$1-O$2
  mkdir ./builds/arm64-clang-$1-O$2
  cp ./unrar    ./builds/arm64-clang-$1-O$2/unrar
}

function do_clang_mips_32 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips-linux-gnu"
  export CC=clang-$1
  export CXX=clang++-$1
  export CFLAGS="-fno-inline-functions -fuse-ld=lld --target=mips-linux-gnu -march=mips32r2 --sysroot=/usr/mips-linux-gnu -O$2 -Wl,-z,notext -I/usr/mips-linux-gnu/include/c++/7/mips-linux-gnu/ -I/usr/mips-linux-gnu/include/c++/7/"
  export CXXFLAGS="-fno-inline-functions -fuse-ld=lld --target=mips-linux-gnu -march=mips32r2 --sysroot=/usr/mips-linux-gnu -O$2 -Wl,-z,notext -I/usr/mips-linux-gnu/include/c++/7/mips-linux-gnu/ -I/usr/mips-linux-gnu/include/c++/7/"
  # Due to the following error, -Wl,-z,notext needs to be added
  # ld.lld: error: can't create dynamic relocation R_MIPS_32 against local symbol in readonly segment; recompile object files with -fPIC or pass '-Wl,-z,notext' to allow text relocations in the output
  export LDFLAGS="-pthread -fuse-ld=lld --target=mips-linux-gnu --sysroot=/usr/mips-linux-gnu"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips32-clang-$1-O$2
  mkdir ./builds/mips32-clang-$1-O$2
  cp ./unrar    ./builds/mips32-clang-$1-O$2/unrar
}

function do_clang_mips_64 {
  unset CROSS_COMPILE
  unset AS
  unset LD
  unset AR
  unset RANLIB
  unset NM
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips64-linux-gnu"
  export CC=clang-$1
  export CXX=clang++-$1
  export CXXFLAGS="-fno-inline-functions -fuse-ld=lld --target=mips64-linux-gnuabi64 -march=mips64r2 --sysroot=/usr/mips64-linux-gnuabi64 -O$2 -Wl,-z,notext -I/usr/mips64-linux-gnuabi64/include/c++/7/mips64-linux-gnuabi64 -I/usr/mips64-linux-gnuabi64/include/c++/7/"
  # Due to the following error, -fPIC needs to be added
  # ld.lld: error: can't create dynamic relocation R_MIPS_32 against local symbol in readonly segment; recompile object files with -fPIC or pass '-Wl,-z,notext' to allow text relocations in the output
  export CFLAGS="-fno-inline-functions -fuse-ld=lld --target=mips64-linux-gnuabi64 -march=mips64r2 --sysroot=/usr/mips64-linux-gnuabi64 -O$2 -Wl,-z,notext -I/usr/mips64-linux-gnuabi64/include/c++/7/mips64-linux-gnuabi64 -I/usr/mips64-linux-gnuabi64/include/c++/7/"
  export LDFLAGS="-pthread -fuse-ld=lld --target=mips64-linux-gnuabi64 --sysroot=/usr/mips64-linux-gnuabi64"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips64-clang-$1-O$2
  mkdir ./builds/mips64-clang-$1-O$2
  cp ./unrar    ./builds/mips64-clang-$1-O$2/unrar
}

# clang -fuse-ld=lld --target=arm-linux-gnu -march=armv8 --sysroot=/usr/arm-linux-gnueabi /tmp/test.c -o /tmp/hello
# clang -fuse-ld=lld --target=mips-linux-gnu -march=mips32r2 --sysroot=/usr/mips-linux-gnu /tmp/test.c -o /tmp/hello
# clang -fuse-ld=lld --target=mips64-linux-gnuabi64 -march=mips64r2 --sysroot=/usr/mips64-linux-gnuabi64 /tmp/test.c -o /tmp/hello

function do_gcc_mips_9_64 {
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips64-linux-gnu"
  export AR=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ar
  export AS=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-as
  export LD=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ld
  export RANLIB=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ranlib
  export CC=/home/dockeruser/gcc-9_mips64/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-gcc
  export NM=/home/dockeruser/gcc-9_mips64/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-nm
  export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
  export CXX=/home/dockeruser/gcc-9_mips64/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-g++
  export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2"
  export LDFLAGS="-pthread"
  export DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
  export LIBFLAGS=-fPIC

  make clean
  make

  rm -rf ./builds/mips64-gcc-$1-O$2
  mkdir ./builds/mips64-gcc-$1-O$2
  cp ./unrar    ./builds/mips64-gcc-$1-O$2/unrar
}


# GCC MIPS64 // 9 must be done on 19.10 / 4.8 must be done differently 
for opt_level in 0 1 2 3 s
do
do_gcc_mips_9_64 9 $opt_level
done

# GCC ARM32 // 9 must be done on 19.10, 4.8 must be done differently 
for opt_level in 0 1 2 3 s
do
do_gcc_arm_32 9 $opt_level
done

# GCC ARM64 // 9 must be done on 19.10 
for opt_level in 0 1 2 3 s
do
do_gcc_arm_64 9 $opt_level
done

# GCC MIPS32 // 9 must be done on 19.10 / 4.8 must be done differently 
for opt_level in 0 1 2 3 s
do
do_gcc_mips_32 9 $opt_level
done
