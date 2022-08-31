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
#  automate_intel_archs.sh - Automate library compilation                    #
#                                                                            #
##############################################################################

# $1 -> gcc version
# $2 -> optimization
function do_gcc_x86 {
  export BUILD_DIR=/media/data/builds_clamav/clamav
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
  export CFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/ -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86"
  export CXXFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/ -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86"
  export LDFLAGS="-fno-inline-functions -m32 -O$2 -Wl,-z,notext -I/usr/i686-linux-gnu/include/ -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86"
  make distclean
  ./configure --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86 --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/x86-gcc-$1-O$2
  mkdir $BUILD_DIR/x86-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/x86-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x86-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/x86-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x86-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/x86-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/x86-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/x86-gcc-$1-O$2/
}

function do_gcc_x64 {
  export BUILD_DIR=/media/data/builds_clamav/clamav
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
  export LDFLAGS="-fno-inline-functions -m64 -O$2 -Wl,-z,notext"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/x64-gcc-$1-O$2
  mkdir $BUILD_DIR/x64-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/x64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x64-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/x64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x64-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/x64-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/x64-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/x64-gcc-$1-O$2/
}

# $1 -> clang version
# $2 -> optimization
function do_clang_x86 {
  export BUILD_DIR=/media/data/builds_clamav/clamav
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
  export CFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86"
  export CXXFLAGS="-fno-inline-functions -m32 -O$2   -I/usr/i686-linux-gnu/include/  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86"
  export LDFLAGS="-fno-inline-functions -m32 -O$2 -Wl,-z,notext -I/usr/i686-linux-gnu/include/ -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/x86 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/x86
  make clean
  make -j 4
  rm -rf $BUILD_DIR/x86-clang-$1-O$2
  mkdir $BUILD_DIR/x86-clang-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/x86-clang-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x86-clang-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/x86-clang-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x86-clang-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/x86-clang-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/x86-clang-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/x86-clang-$1-O$2/

}


# $1 -> clang version
# $2 -> optimization
function do_clang_x64 {
  export BUILD_DIR=/media/data/builds_clamav/clamav
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
  export CFLAGS="-fno-inline-functions -m64 -O$2 "
  export CXXFLAGS="-fno-inline-functions -m64 -O$2"
  export LDFLAGS="-fno-inline-functions -m64 -O$2 -Wl,-z,notext"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/x64-clang-$1-O$2
  mkdir $BUILD_DIR/x64-clang-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/x64-clang-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x64-clang-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/x64-clang-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/x64-clang-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/x64-clang-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/x64-clang-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/x64-clang-$1-O$2/
}

# x86-64 GCC
for gcc_v in 4.8 5 7 9
do
    for opt_level in 0 1 2 3 s
    do
        do_gcc_x86 $gcc_v $opt_level
    done
done

# x86-64 GCC
for gcc_v in 4.8 5 7 9
do
    for opt_level in 0 1 2 3 s
    do
        do_gcc_x64 $gcc_v $opt_level
    done
done

# x86-64 CLANG
for clang_v in 3.5 5.0 7 9
do
    for opt_level in 0 1 2 3 s
    do
        do_clang_x86 $clang_v $opt_level
    done
done

# x86-64 CLANG
for clang_v in 3.5 5.0 7 9
do
    for opt_level in 0 1 2 3 s
    do
        do_clang_x64 $clang_v $opt_level
    done
done
