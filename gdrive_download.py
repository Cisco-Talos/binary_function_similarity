#!/usr/bin/env python
# coding: utf-8

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
#  gdrive_download.py - Download the dataset from Google Drive               #
#                                                                            #
##############################################################################

import click
import gdown
import hashlib
import os
import zipfile

BINARIES_DICT = {
    "Dataset-1.zip": "1QpRgVJZTM52bfB6PvCKwVnmkKdHenUai",
    "Dataset-2.zip": "11_opEXH-WAKQs_WjCEx97aibOPlGIhm7",
    "Dataset-Vulnerability.zip": "1i9CEJ7IGwyFF_3VlQWVsJRVW1XMXy96Z"
}
FEATURES_DICT = {
    "Dataset-1/features.zip": "1gu7ZEhpg3JkznX3_VV2SBCyc6LO7sX2q",
    "Dataset-1-CodeCMR/features.zip": "1LoXaMSyDFkHlAzMEuZslE_mMi2yo2LZz",
    "Dataset-2/features.zip": "1Dp3MvTfIAG4iakjlAGqbsX_Y3Na_c_t8",
    "Dataset-Vulnerability/features.zip": "1NOL5DBem1TbI2Lcc0R64L7JM1BnJMDSp"
}
SHA256_DICT = {
    "Dataset-1.zip":
    "f45edac9a7414c3bef77b271bcba083656e148d08d2da8ed5d667d887af35e46",
    "Dataset-2.zip":
    "fdedb72966e029f1e9d4e3f5f67bbd722f4a0c4c52e4ec3cf7152e916a7bc750",
    "Dataset-Vulnerability.zip":
    "0b916bd0fc5107e34d5d06c0e7037337b6e0dc5042b475ca3be5ccba7d7d1bd7",
    "Dataset-1/features.zip":
    "23a154929ac0600ac5a5893689088f166e1b34fd526f1fc45b6d9cf06ff987f5",
    "Dataset-1-CodeCMR/features.zip":
    "dc51c60189f65fa0a000bd2a1afa1fbc278e4a7164eebe5d1b47c90afaf2d98b",
    "Dataset-2/features.zip":
    "fe54af04ba2ca6de465e676194514cd85421c52d29a7ca8facccb2673d5b5705",
    "Dataset-Vulnerability/features.zip":
    "fd4677a349a198b5332742fc09eb6209ed3a5b3e463f7083a09a7ae398316742",
}
REPO_PATH = (os.path.dirname(os.path.abspath(__file__)))
BINARIES_FOLDER = os.path.join(REPO_PATH, "Binaries")
DATASET_FOLDER = os.path.join(REPO_PATH, "DBs")
MODELS_FOLDER = os.path.join(REPO_PATH, "Models")


def compute_sha256(file_path):
    """Compute the sha256 for the file in file_path."""
    blocksize = 65536
    sha = hashlib.sha256()
    with open(file_path, 'rb') as f_in:
        file_buffer = f_in.read(blocksize)
        while len(file_buffer) > 0:
            sha.update(file_buffer)
            file_buffer = f_in.read(blocksize)
    return sha.hexdigest()


def download_binaries():
    """Download and unzip the archives containing the binaries for the exp."""
    try:
        if not os.path.isdir(BINARIES_FOLDER):
            os.mkdir(BINARIES_FOLDER)

        for zip_name, gid in BINARIES_DICT.items():
            temp_dir = os.path.join(BINARIES_FOLDER, zip_name.split(".")[0])
            if os.path.isdir(temp_dir):
                print("[W] {} already exists".format(temp_dir))
                continue

            zip_path = os.path.join(BINARIES_FOLDER, zip_name)
            print("Downloading {} ...".format(zip_name))
            gdown.download(id=gid, output=zip_path, quiet=False)

            if not os.path.isfile(zip_path):
                print("[!] Error: file {} not found".format(zip_path))
                continue

            print("Checking checksum {} ...".format(zip_name))
            sha = compute_sha256(zip_path)
            if sha != SHA256_DICT[zip_name]:
                print("[!] Checksum error: {} != {}".format(
                    sha, SHA256_DICT[zip_name]))
                continue

            print("Extracting archive to {}...".format(BINARIES_FOLDER))
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(BINARIES_FOLDER)

            os.remove(zip_path)
            print()
    except Exception as e:
        print("[!] Exception in download_binaries\n{}".format(e))


def download_features():
    """Download and unzip the archives containing the features for the exp."""
    try:
        if not os.path.isdir(DATASET_FOLDER):
            os.mkdir(DATASET_FOLDER)

        for zip_name, gid in FEATURES_DICT.items():
            temp_dir = os.path.join(DATASET_FOLDER, zip_name.split(".")[0])
            if os.path.isdir(temp_dir):
                print("[W] {} already exists".format(temp_dir))
                continue

            zip_path = os.path.join(DATASET_FOLDER, zip_name)
            print("Downloading {} ...".format(zip_name))
            gdown.download(id=gid, output=zip_path, quiet=False)

            if not os.path.isfile(zip_path):
                print("[!] Error: file {} not found".format(zip_path))
                continue

            print("Checking checksum {} ...".format(zip_name))
            sha = compute_sha256(zip_path)
            if sha != SHA256_DICT[zip_name]:
                print("[!] Checksum error: {} != {}".format(
                    sha, SHA256_DICT[zip_name]))
                continue

            print("Extracting archive to {}...".format(DATASET_FOLDER))
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(os.path.dirname(zip_path))

            os.remove(zip_path)
            print()

    except Exception as e:
        print("[!] Exception in download_features\n{}".format(e))


@click.command()
@click.option('--binaries', is_flag=True)
@click.option('--features', is_flag=True)
def main(binaries, features):
    """Download the dataset from Google Drive."""
    if binaries:
        download_binaries()
    if features:
        download_features()
    print("That's all")


if __name__ == "__main__":
    main()
