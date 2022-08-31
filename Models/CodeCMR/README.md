# BinaryAI / CodeCMR
The BinaryAI / CodeCMR experiment consists of two steps. The first is an IDA Pro plugin that takes as input a JSON specifying which functions to consider for the tests, and as output it produces intermediate results in pickle format. In the second step a neural network is trained to recognise similar functions. The output of the neural network is a vector representation for each function. We release only [Part 1](#part-1), since the authors of the CodeCMR paper trained and tested the model for us (more information in the [technical report](../../Additional technical information.pdf)).

## Part 1
Before running the IDA plugin, follow the list of requirements from the IDA_scripts [README](../../../IDA_scripts/README.md#requirements)

- **Input**: the JSON file with the selected functions (`-j`) and the output directory (`-o`).
- **Output**: one pickle file per IDB. The file contains a serialized version of a NetworkX graph (with the extracted features) for each function analyzed in the IDB.

**Notes**:
* The plugin requires the IDA Pro decompiler license
* IDA Pro [requires](https://hex-rays.com/blog/igors-tip-of-the-week-40-decompiler-basics/) 32-bit IDA to decompile 32-bit binaries and 64-bit IDA for 64-bit binaries.
32-bit binaries need to be exported to `.idb` format, while 64-bit binaries require `.i64` format.
* The path of the IDB files in the JSON in input **must be relative** to the `binary_function_similarity` directory. The Python3 script converts the relative path into a full path to correctly load the IDB in IDA Pro.

Example: run the plugins over the functions selected for the Dataset-1-CodeCMR test (requires the `.i64` IDBs for 64-bit binaries and `.idb` for 32-bit binaries)
```bash
cd IDA_CodeCMR
python3 cli_codeCMR.py -j ../../../DBs/Dataset-1-CodeCMR/features/selected_Dataset-1-CodeCMR.json -o Dataset-1-CodeCMR
```

Run unit tests:
```bash
python3 -m unittest test_codeCMR.py
```

## Copyright information about the BinaryAI / CodeCMR plugin

[IDA_CodeCMR.py](IDA_CodeCMR.py) includes part of the code from https://github.com/binaryai/sdk/ which is licensed under GPL-3.0.