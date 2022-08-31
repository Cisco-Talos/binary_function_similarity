# The IDA Pro scripts

This folder contains:
* [one script](generate_idbs.py) to generate IDBs from the compiled binaries
* several [IDA Pro plugins](#the-ida-pro-plugins) used for the features extraction.

## Requirements

1. Set the `IDA32_PATH` and `IDA_PATH` environment variables with the full path of `idat` and `idat64`. Example:
```bash
export IDA_PATH=/home/user/idapro-7.3/idat64
export IDA32_PATH=/home/user/idapro-7.3/idat
```

2. Install the Python3 [virtualenv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/#installing-virtualenv)

3. Create a new virtualenv and install the required packages
```bash
# create a new "env" environment
python3 -m venv env
# enter the virtual environment
source env/bin/activate

# Install the requirements in the current environment
pip install -r requirements.txt
```

4. (To replicate our results) Install `Capstone 3.0.4` in the *IDA Pro Python2 environment*:
```bash
pip2 install capstone==3.0.4
```

5. (To run the CodeCMR plugin) Install `networkx 2.5` in the *IDA Pro Python3 environment*:
```bash
pip3 install networkx==2.5
```

6. Export the IDBs used for the unit tests of the IDA plugins:
```bash
python3 generate_idbs.py --test
```


## Generate the IDBs (IDA databases)

Use the [generate_idbs.py](generate_idbs.py) Python3 script to automatically export the IDBs for the binaries of each dataset:
- **Input**: the flag corresponding to the dataset to process (`--db1`, `--db2`, `--dbvuln`)
- **Output**: the corresponding IDBs and a log file (`generate_idbs_log.txt`)

Example: generate the IDBs for the [Dataset-Vulnerability](../Binaries/Dataset-Vulnerability) (the smallest, with only six binaries)
```bash
python3 generate_idbs.py --dbvuln
```

Example: generate the IDBs for all the binaries in the [Binaries](../Binaries/) folder (this will **take hours** and **several GB** of disk space)
```bash
python3 generate_idbs.py --db1 --db2 --dbvuln
```


## The IDA Pro Plugins

**Notes**:
* Most of the IDA plugins have been written for *IDA Pro 7.3 Linux x86_64* and Python 2. A new version compatible with *IDA Pro 7.4+* and Python 3 *may be released* in the future. The only exception is the CodeCMR plugin that was released by the authors for *IDA Pro 7.4+* and Python3 (it's also the only one that requires the HexRays decompiler).
* All the plugins follow the same pattern: a Python3 script (`cli_*.py`) calls the IDA Pro Python2 plugin (`IDA_*.py`) in sequential mode (no multiprocessing) on each binary to avoid saturating IDA Pro floating licenses.

---

### IDA FlowChart
**Summary**: it extracts basic information from each function with at least five basic blocks.

- **Input**: the folder with the IDBs (`-i`) and the name of the CSV file in output (`-o`).
- **Output**: one CSV file with all the functions with at least five basic blocks.

Example: run the plugin over the IDBs of the Dataset-Vulnerability (requires the IDBs in the `IDBs/Dataset-Vulnerability` directory)
```bash
cd IDA_flowchart
python3 cli_flowchart.py -i ../../IDBs/Dataset-Vulnerability -o flowchart_Dataset-Vulnerability.csv
```

Run unit tests:
```bash
python3 -m unittest test_flowchart.py

# optional - test on multiple files
python3 -m unittest test_large_flowchart.py
```

---

### IDA ACFG-disasm
**Summary**: it creates an ACFG with the basic-blocks disassembly for each selected function.

- **Input**: a JSON file with the selected functions (`-j`) and the name of a folder in output (`-o`).
- **Output**: one JSON file (`_acfg_disasm.json`) per IDB.

**Note**: the path of the IDB files in the JSON in input **must be relative** to the `binary_function_similarity` directory. The Python3 script converts the relative path into a full path to correctly load the IDB in IDA Pro.

Example: run the plugin over the functions selected for the Dataset-Vulnerability test (requires the IDBs in the `IDBs/Dataset-Vulnerability` directory)
```bash
cd IDA_acfg_disasm
python3 cli_acfg_disasm.py -j ../../DBs/Dataset-Vulnerability/features/selected_Dataset-Vulnerability.json -o acfg_disasm_Dataset-Vulnerability
```

Run unit tests:
```bash
python3 -m unittest test_acfg_disasm.py

# optional - test on multiple files
python3 -m unittest test_large_acfg_disasm.py
```

---

### IDA ACFG-features
**Summary**: it creates an ACFG with the Genius/Gemini features for each selected function.

- **Input**: a JSON file with the selected functions (`-j`) and the name of a folder in output (`-o`).
- **Output**: one JSON file (`_acfg_features.json`) per IDB.

**Note**: the path of the IDB files in the JSON in input **must be relative** to the `binary_function_similarity` directory. The Python3 script converts the relative path into a full path to correctly load the IDB in IDA Pro.

Example: run the plugin over the functions selected for the Dataset-Vulnerability test (requires the IDBs in the `IDBs/Dataset-Vulnerability` directory)
```bash
cd IDA_acfg_features
python3 cli_acfg_features.py -j ../../DBs/Dataset-Vulnerability/features/selected_Dataset-Vulnerability.json -o acfg_features_Dataset-Vulnerability
```

Run unit tests:
```bash
python3 -m unittest test_acfg_features.py

# optional - test on multiple files
python3 -m unittest test_large_acfg_features.py
```

---

### IDA FunctionSimSearch
**Summary**: it extracts the features used by the FunctionSimSearch approach.

This plugin is located in the [Models/FunctionSimSearch](../Models/functionsimsearch/) directory.

---

### IDA Catalog1
**Summary**: it extracts the Catalog1 fuzzy hashes.

This plugin is located in the [Models/Catalog1](../Models/Catalog1/) directory.

---

### IDA CodeCMR
**Summary**: it extracts the features used in the CodeCMR/BinaryAI model.

This plugin is located in the [Models/CodeCMR](../Models/CodeCMR/) directory.
