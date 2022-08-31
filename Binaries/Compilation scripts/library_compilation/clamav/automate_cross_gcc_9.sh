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

function do_gcc_arm_32 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="arm-linux-gnueabi"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=armv8-a -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm32"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm32"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu  --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm32 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm32 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/arm32-gcc-$1-O$2
  mkdir $BUILD_DIR/arm32-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/arm32-gcc-$1-O$2/
}

function do_gcc_arm_48_32 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="arm-linux-gnueabi"
  export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ar
  export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-as
  export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ld
  export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-ranlib
  export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-gcc
  export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-nm
  export CFLAGS="-fno-inline-functions -march=armv8-a -O$2  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm32"
  export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_arm/install_dir/bin/arm-linux-gnueabi-g++
  export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm32"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu  --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm32 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm32 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/arm32-gcc-$1-O$2
  mkdir $BUILD_DIR/arm32-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/arm32-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/arm32-gcc-$1-O$2/

}

function do_gcc_arm_64 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="aarch64-linux-gnu"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=armv8-a -O$2  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm64"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=armv8-a -O$2  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm64"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu  --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/arm64 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/arm64 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/arm64-gcc-$1-O$2
  mkdir $BUILD_DIR/arm64-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/arm64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/arm64-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/arm64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/arm64-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/arm64-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/arm64-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/arm64-gcc-$1-O$2/
}

function do_gcc_mips_32 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips-linux-gnu"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=mips32r2 -O$2  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=mips32r2 -O$2  -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no  --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu  --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/mips32-gcc-$1-O$2
  mkdir $BUILD_DIR/mips32-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/mips32-gcc-$1-O$2/
}

function do_gcc_mips_48_32 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips-linux-gnu"
  export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ar
  export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-as
  export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ld
  export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-ranlib
  export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-gcc
  export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-nm
  export CFLAGS="-fno-inline-functions -march=mips32r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32"
  export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips/install_dir/bin/mips-linux-g++
  export CXXFLAGS="-fno-inline-functions -march=mips32r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32"
  #export LDFLAGS="-L/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32/lib -L/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32/lib"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips32 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips32
  make clean
  make -j 4
  rm -rf $BUILD_DIR/mips32-gcc-$1-O$2
  mkdir $BUILD_DIR/mips32-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/mips32-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/mips32-gcc-$1-O$2/
}

function do_gcc_mips_64 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips64-linux-gnuabi64"
  export AR=${CROSS_COMPILE}-ar
  export AS=${CROSS_COMPILE}-as
  export LD=${CROSS_COMPILE}-ld
  export RANLIB=${CROSS_COMPILE}-ranlib
  export CC=${CROSS_COMPILE}-gcc-$1
  export NM=${CROSS_COMPILE}-nm
  export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64"
  export CXX=${CROSS_COMPILE}-g++-$1
  export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64"
  make distclean
  ./configure --disable-pthreads  --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu  --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64 
  make clean
  make -j 4
  rm -rf $BUILD_DIR/mips64-gcc-$1-O$2
  mkdir $BUILD_DIR/mips64-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/mips64-gcc-$1-O$2/
}

function do_gcc_mips_48_64 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips64-linux-gnu"
  export AR=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ar
  export AS=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-as
  export LD=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ld
  export RANLIB=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-ranlib
  export CC=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-gcc
  export NM=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-nm
  export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64"
  export CXX=/mnt/hgfs/first_training_dataset/gcc-4.8.5_mips64/install_dir/bin/mips64-linux-gnuabi64-g++
  export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64"
  make distclean
  ./configure --disable-pthreads --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64
  make clean
  make -j 4
  rm -rf $BUILD_DIR/mips64-gcc-$1-O$2
  mkdir $BUILD_DIR/mips64-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/mips64-gcc-$1-O$2/
}


function do_gcc_mips_9_64 {
  export BUILD_DIR=./builds
  unset LIBS
  unset LDFLAGS
  export CROSS_COMPILE="mips64-linux-gnu"
  export AR=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ar
  export AS=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-as
  export LD=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ld
  export RANLIB=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-ranlib
  export CC=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-gcc
  export NM=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-nm
  export CFLAGS="-fno-inline-functions -march=mips64r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64"
  export CXX=/home/dockeruser/gcc-9_mips64/install_dir/bin/mips64-linux-gnuabi64-g++
  export CXXFLAGS="-fno-inline-functions -march=mips64r2 -O$2 -I/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 -I/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64"
  make distclean
  ./configure --disable-pthreads --disable-llvm --with-pcre=no --disable-xml --disable-bzip2 --disable-static --with-systemdsystemunitdir=no --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu --with-openssl=/mnt/hgfs/first_training_dataset/openssl/openssl/installs/mips64 --with-zlib=/mnt/hgfs/first_training_dataset/zlib/zlib/installs/mips64
  make clean
  make -j 4
  rm -rf $BUILD_DIR/mips64-gcc-$1-O$2
  mkdir $BUILD_DIR/mips64-gcc-$1-O$2
  cp ./libclamav/.libs/libclamav.so.9.0.0 $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./sigtool/.libs/sigtool              $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamscan/.libs/clamscan            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clamconf/.libs/clamconf            $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./freshclam/.libs/freshclam          $BUILD_DIR/mips64-gcc-$1-O$2/
  cp ./clambc/.libs/clambc                $BUILD_DIR/mips64-gcc-$1-O$2/
}

# GCC ARM64 // 9 must be done on 19.10 
for gcc_v in 9 
do
    for opt_level in 0 1 2 3 s
    do
       do_gcc_arm_64 $gcc_v $opt_level
    done
done

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



