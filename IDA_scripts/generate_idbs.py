#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
#  generate_idbs.py - Analyse the binary with IDA Pro and save the IDB       #
#                                                                            #
##############################################################################

import click
import subprocess

from os import getenv
from os import makedirs
from os import mkdir
from os import walk
from os.path import abspath
from os.path import dirname
from os.path import isdir
from os.path import isfile
from os.path import join
from os.path import relpath
from os.path import samefile


BIN_FOLDER = join(dirname(dirname(abspath(__file__))), 'Binaries')
IDB_FOLDER = join(dirname(dirname(abspath(__file__))), 'IDBs')
IDA_PATH = getenv("IDA_PATH", "/home/user/idapro-7.3/idat64")
LOG_PATH = "generate_idbs_log.txt"

TEST_BINARIES = {
    "nmap/arm32-clang-5.0-O0_ncat": "arm32-clang-5.0-O0_ncat.i64",
    "nmap/arm64-clang-7-O2_ncat": "arm64-clang-7-O2_ncat.i64",
    "nmap/mips32-clang-3.5-O0_ncat": "mips32-clang-3.5-O0_ncat.i64",
    "nmap/mips32-clang-7-O3_nmap": "mips32-clang-7-O3_nmap.i64",
    "nmap/mips64-clang-3.5-O0_ncat": "mips64-clang-3.5-O0_ncat.i64",
    "nmap/mips64-clang-3.5-O1_nmap": "mips64-clang-3.5-O1_nmap.i64",
    "nmap/x64-clang-3.5-Os_ncat": "x64-clang-3.5-Os_ncat.i64",
    "nmap/x86-clang-3.5-O0_ncat": "x86-clang-3.5-O0_ncat.i64",
    "nmap/x86-gcc-5-O2_ncat": "x86-gcc-5-O2_ncat.i64",
    "z3/arm64-clang-5.0-O0_z3": "arm64-clang-5.0-O0_z3.i64",
    "z3/x64-clang-3.5-O0_z3": "x64-clang-3.5-O0_z3.i64"
}


def export_idb(input_path, output_path):
    """Launch IDA Pro and export the IDB. Inner function."""
    try:
        print("Export IDB for {}".format(input_path))
        ida_output = str(subprocess.check_output([
            IDA_PATH,
            "-L{}".format(LOG_PATH),  # name of the log file. "Append mode"
            "-a-",  # enables auto analysis
            "-B",  # batch mode. IDA will generate .IDB and .ASM files
            "-o{}".format(output_path),
            input_path
        ]))

        if not isfile(output_path):
            print("[!] Error: file {} not found".format(output_path))
            print(ida_output)
            return False

        return True

    except Exception as e:
        print("[!] Exception in export_idb\n{}".format(e))


def directory_walk(input_folder, output_folder):
    """Walk the directory tree and launch IDA Pro."""
    try:
        print("[D] input_folder: {}".format(input_folder))
        print("[D] output_folder: {}".format(output_folder))

        export_error, export_success = 0, 0
        if not input_folder or not output_folder:
            print("[!] Error: missing input/output folder")
            return

        if not isdir(output_folder):
            mkdir(output_folder)

        for root, _, files in walk(input_folder):
            for fname in files:
                if fname.endswith(".log") \
                        or fname.endswith(".idb") \
                        or fname.endswith(".i64"):
                    continue

                tmp_out = output_folder
                if not samefile(root, input_folder):
                    tmp_out = join(
                        output_folder,
                        relpath(root, input_folder))
                    if not isdir(tmp_out):
                        makedirs(tmp_out)

                input_path = join(root, fname)
                output_path = join(tmp_out, fname + ".i64")
                if export_idb(input_path, output_path):
                    export_success += 1
                else:
                    export_error += 1

        print("# IDBs correctly exported: {}".format(export_success))
        print("# IDBs error: {}".format(export_error))

    except Exception as e:
        print("[!] Exception in directory_walk\n{}".format(e))


@click.command()
@click.option('--db1', is_flag=True)
@click.option('--db2', is_flag=True)
@click.option('--dbvuln', is_flag=True)
@click.option('--test', is_flag=True)
def main(db1, db2, dbvuln, test):
    """Launch IDA Pro and export the IDBs."""
    if not isfile(IDA_PATH):
        print("[!] Error: IDA_PATH:{} not valid".format(IDA_PATH))
        print("Use 'export IDA_PATH=/full/path/to/idat64'")
        return
    no_action = True

    if db1:
        no_action = False
        directory_walk(
            join(BIN_FOLDER, 'Dataset-1'),
            join(IDB_FOLDER, 'Dataset-1'))
    if db2:
        no_action = False
        directory_walk(
            join(BIN_FOLDER, 'Dataset-2'),
            join(IDB_FOLDER, 'Dataset-2'))
    if dbvuln:
        no_action = False
        directory_walk(
            join(BIN_FOLDER, 'Dataset-Vulnerability'),
            join(IDB_FOLDER, 'Dataset-Vulnerability'))
    if test:
        no_action = False
        output_folder = join(IDB_FOLDER, "Dataset-1")
        if not isdir(output_folder):
            mkdir(output_folder)
        for k, v in TEST_BINARIES.items():
            output_path = join(output_folder, v)
            if isfile(output_path):
                print("[D] {} already exists".format(output_path))
                continue
            export_idb(
                join(BIN_FOLDER, "Dataset-1", k),
                output_path)

    if no_action:
        print("Please, select a Dataset to process. --help for options")
    else:
        print("That's all")
    return


if __name__ == "__main__":
    main()
