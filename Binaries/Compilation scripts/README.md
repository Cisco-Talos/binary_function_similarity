# Compiled binaries
This folder contains the documentation and scripts necessary to compile the binaries for the **Dataset-1**.


## Compilers and versions

We compiled the binaries from **Dataset-1** in two different environments: Ubuntu 18.04 and 19.04, based on the availability of packages in their corresponding package repositories. Unfortunately these linux distributions did not cover all the cross-compiler versions we needed to generate this dataset, so we manually compiled those toolchains (including their associated C runtime, library headers and compiler tools). In every case we leveraged the closest possible package version when the same exact version was not available, or we compiled it manually if no version was available.

### Compilers distributed from package repositories in Ubuntu 18.04
| Compiler  |                x86 |                x64 |              ARM32 |              ARM64 |             MIPS32 |             MIPS64 |
| --------- | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ |
| gcc-4.8.5 | :white_check_mark: | :white_check_mark: |                    | :white_check_mark: |                    |                    |
| gcc-5.5.0 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| gcc-7.4.0 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| gcc-9.2.1 | :white_check_mark: | :white_check_mark: |                    |                    |                    |                    |
| clang 3.5 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| clang 5.0 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| clang 7   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| clang 9   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Compilers distributed from package repositories on Ubuntu 19.04
| Compiler  |                x86 |                x64 |              ARM32 |              ARM64 |             MIPS32 |             MIPS64 |
| --------- | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ |
| gcc-9.1.0 |                    |                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    | 

### Additional compiler toolchains manually compiled on Ubuntu 18.04
  * `mips64-linux-gnuabi64-gcc-4.8.5`
  * `mips-linux-gcc-4.8.5 `
  * `arm-linux-gnueabi-g++-4.8.5`

### Additional compiler toolchains manually compiled on Ubuntu 19.04:
  * `gcc-9.1.0` (MIPS64)


## Step 1: Setting up the environments

### Setup for Ubuntu 18.04
Add the necessary repositories:

- Uncomment all the deb-src entries in `/etc/apt/sources.list`

- Add the following lines to `/etc/sources.list`
```
deb http://ppa.launchpad.net/george-edison55/cmake-3.x/ubuntu xenial main
deb-src http://ppa.launchpad.net/george-edison55/cmake-3.x/ubuntu xenial main

deb http://dk.archive.ubuntu.com/ubuntu/ xenial main
deb http://dk.archive.ubuntu.com/ubuntu/ xenial universe
```

- Add the following apt-repository
```bash
sudo add-apt-repository ppa:jonathonf/gcc-9.0
```

- Add the following apt-key:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 084ECFC5828AB726
```

- Install the package list from this file [file](os_install_packages/ubuntu1804/package_list):
```bash
sudo apt-get update
sudo apt-get install `cat os_install_packages/ubuntu1804/package_list`
```

### Setup for Ubuntu 19.04
- At the time of publication of this paper (June 2022), this Ubuntu version has already reached its end of life. For this reason,
it is necessary to modify the package repository servers listed in `/etc/apt/sources.list`, replacing both `archive.ubuntu.com`
and `security.ubuntu.com` by `old-releases.ubuntu.com`.
- Install the package list from this file [file](os_install_packages/ubuntu1904/package_list):
```bash
sudo apt-get update
sudo apt-get install `cat os_install_packages/ubuntu1904/package_list`
```


## Step 2: Compiling missing compiler tool-chains

The following [website](https://preshing.com/20141119/how-to-build-a-gcc-cross-compiler/) provides a good reference 
about building gcc cross compiler toolchains, including a [script](https://gist.github.com/preshing/41d5c7248dea16238b60) 
that automates all the steps described. The rest of this section describes several tips and lessons learnt.

It is convenient to run the script in two phases. First, run the first section of the script that downloads
the necessary packages from `ftp://gcc.gnu.org` to then uncompress them. You may want to apply the following modifications
to simplify package building:

- In `gcc-4.8.5/gcc/Makefile.in`, remove the `doc` subtargets under the `all.internal` and `all.cross` targets, so that it ends up like this:
```bash
all.internal: start.encap rest.encap # doc
# This is what to compile if making a cross-compiler.
all.cross: native gcc-cross$(exeext) cpp$(exeext) specs \
  libgcc-support lang.all.cross @GENINSRC@ srcextra # doc 
```

- Remove the `install-man` and `install-info` subtargets under the `install` target, so that it ends up like this:
```bash
# # install-man install-info
install: install-common $(INSTALL_HEADERS) \
    install-cpp  install-@POSUB@ \
    install-driver install-lto-wrapper install-gcc-ar
```

Then, run the second part of the script, where you need to change the following lines:
```bash
INSTALL_PATH=/your_path/gcc-4.8.5_mips64/install_dir
TARGET=mips64-linux
LINUX_ARCH=mips
GCC_VERSION=gcc-4.8.5
```

- `LINUX_ARCH` is `mips` both for `mips` and `mips64`. `TARGET` can be `mips-linux` or `mips64-linux-gnuabi64`.

- For `mips64`, it may happen that it generates binaries with the 32 bit ABI (see [this](https://t2.t2-project.narkive.com/FKyJIQXs/mips64-multilib-build-is-not-defaulting-to-64-bit-libraries)).
You can solve this by adding the following `CPPFLAGS` env var when configuring glibc, otherwise glibc
assumes `m32 ABI` even for MIPS64, and will produce 32bit ABI binaries with MIPS64 code.
```bash
CPPFLAGS=-mabi=64 ../$GLIBC_VERSION/configure --prefix=$INSTALL_PATH/$TARGET --build=$MACHTYPE --host=$TARGET --target=$TARGET --with-headers=$INSTALL_PATH/$TARGET/include $CONFIGURATION_OPTIONS libc_cv_forced_unwind=yes
```

Additional tips and lessons learnt:

- For the following `Makefiles/Makerules`, replace the `ln -f` by `ln -sf` so that they become symbolic links instead of hard links, otherwise it will not work if the files reside in an external (non ext-4) mount.
```bash
glibc-2.20/Makerules: ln -f $< $@
glibc-2.20/nptl/Makefile: ln -f $< $@
glibc-2.20/nptl/Makefile: ln -f $< $@
glibc-2.20/nptl/Makefile: ln -f $< $@
glibc-2.20/posix/Makefile:    ln -f $< $@/$$spec.new || $(INSTALL_PROGRAM) $< $@/$$spec.new; \
```

- For compiling `gcc-9`, it is important to do it in a case sensitive file system (VM shared directories and some virtual
file systems may not be case sensitive).


## Step 3: Compiling the binaries

### Step 3.1: Download the source from the following locations:
* UnRAR:
  - Direct download: https://www.rarlab.com/rar/unrarsrc-5.5.3.tar.gz

* ClamAV:
  - Git repository: https://github.com/Cisco-Talos/clamav-devel.git
  - branch: `dev/0.102`, commit: `ee5a160840309eb933e73f4268a1e67f9e77961d`

* Curl
  - Git repository: https://github.com/curl/curl
  - branch: `master`, commit: `d81dbae19f8876ad472e445d89760970c79cceaa`
 
* Nmap
  - Direct download: https://nmap.org/dist/nmap-7.80.tar.bz2

* OpenSSL
  - Git repository: https://github.com/openssl/openssl.git
  - branch: `master`, commit: `187753e09ceab4c85a0041844e749658e8f712d3`

* Zlib
  - Git repository: https://github.com/madler/zlib
  - branch: `master`, commit: `cacf7f1d4e3d44d871b605da3b647f07d718623f`

* Z3
  - Git repository: https://github.com/Z3Prover/z3
  - branch: `master`, commit: `0b486d26daea05f918643a9d277f12027f0bc2f6`

### Step 3.2: Apply the patches

* **Clamav**:
  - Apply the patch to the configure file: `git apply configure.patch`
  - ClamAV requires full installations of Zlib and OpenSSL. We can compile these libraries for each architecture in order to configure ClamAV building script to point to them (with-ssl, with-zlib options). We provide a helper script under the `openssl/` and the `zlib` directories named `automate_all_for_clam.sh` that can be used to generate the required libraries.

* **Z3**:
  - Apply the patches: `git apply configure.patch`
  - For certain configurations to work (clang, x86), it is necessary to apply a patch: `git apply configure.patch`.
    This patch follows what was suggested [here](https://github.com/Z3Prover/z3/commit/a5caa506067a949afc445c5bf467fe8403538ec9#diff-e95ea02ae1c673c48466cea3546738a7)
    and [here](https://github.com/Z3Prover/z3/issues/1444).
  - Note that Z3 has a hardcoded flag that must be removed: `git apply configure.patch`

* **Nmap** 
  - On certain configurations and architectures, FORTIFY SOURCE produces errors for -O1 and onwards, so we remove the following line from `Makefile.in`: `#DEFS += -D_FORTIFY_SOURCE=2`.

* **Unrar**
  - If needed, the Makefile for unrar can be found [here](https://github.com/pmachapman/unrar/blob/master/makefile)

### Step 3.3: Launch the compilation script
To automate the binary compilation, use the scripts in the [library_compilation](library_compilation/) directory.
Copy the corresponding script to the directory where the project source is located and run the script.

---

## Additional notes and links:

### Notes about architectures used during compilation

#### Intel

- Intel x86 (32 bits)
- Intel x64 (64 bits)

#### ARM

In the case of ARM 32 bits, we use the following architecture version: ARM 32 bit v8 with no FPU, no SIMD, no CRYPTO, no CRC extensions.
Unlike newer versions, Clang 3.5 only supports ARM versions up to v8.
```
($ llvm-as-3.5 < /dev/null | llc-3.5 -march=arm -mcpu=help)
($ llvm-as-9 < /dev/null | llc-9 -march=arm -mcpu=help)
```
To ensure that all the binaries use the same version, we use v8 with no extensions (no hardware FPU, no SIMD, no crypto, no crc, and so on).
Regarding the FPU, note that certain Ubuntu packages such as the gcc-4.8 ARM cross compiler are configured for target gnueabihf, which means that they will force the hardware FPU (hf). For this case, we compile manually gcc-4.8.5 for target "arm-linux-gnueabi" to have a consistent ARM instruction set on all the architectures.

In the case of ARM 64 bits, we use the following architecture version: ARM 64 bit v8 (Aarch64) with no FPU, no SIMD, no CRYPTO, no CRC extensions.

#### MIPS

MIPS r2 seems to be the latest version supported by all compiler versions:

- MIPS32 r2
- MIPS64 r2

### Relevant compiler options and flags.
- All libraries have been compiled with function inlining disabled (GCC, CLANG: -fno-inline-functions,)
- All libraries have been compiled with the following optimization levels. (GCC, CLANG: O0, O1, O2, O3, Os.)
