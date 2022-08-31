# Binaries

## Download the binaries

**Warning: the following steps will require about 15GB of free disk space.**

To download the binaries from [Google Drive](https://drive.google.com/drive/folders/1g9P0KKSwqdFt0K6dDeKKhWfmhqiQHQqU?usp=sharing) use the [`gdrive_download.py`](../gdrive_download.py) Python3 script and follow the instructions below:

1. Install the Python3 [virtualenv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/#installing-virtualenv)

2. Create a new virtualenv and install the required packages
```bash
# create a new "env" environment
python3 -m venv ../env
# enter the virtual environment
source ../env/bin/activate

# Install the requirements in the current environment
pip install -r ../requirements.txt
```

3. Download and unzip the binaries in the corresponding folders:
```bash
python3 ../gdrive_download.py --binaries
```

The binaries will be unzipped in the following directories:
```bash
Binaries/Dataset-Vulnerability
Binaries/Dataset-1
Binaries/Dataset-2
```

## [Alternative] Compile the binaries from the source code

* The instructions to cross-compile the binaries of `Dataset-1` can be found in the [Compilation scripts](Compilation scripts) folder
* Binaries from `Dataset-2` and `Dataset-Vulnerability` are a subset of those released by Trex [1]. Link to the [original dataset](https://github.com/CUMLSec/trex#dataset).

[1] Pei, Kexin, et al. "Trex: Learning execution semantics from micro-traces for binary similarity." arXiv preprint arXiv:2012.08680 (2020).
