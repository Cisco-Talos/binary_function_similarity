# FSS: Function Sim Search
The FSS experiment is made via two steps. [The first](#part-1) is an IDA Pro plugin that takes as input a JSON specifying which functions to consider for the tests, and as output it produces intermediate results in JSON format. [The second part](#part-2) takes as input the JSONs produced by the first part, and it produces as output four CSVs, each of which contains the results of the experiments performed with specific configurations (more details below).

This tool is based on this project by Thomas Dullien: https://github.com/googleprojectzero/functionsimsearch. We forked the repository (commit `ec5d9e1224ff915b3dc9e7af19e21e110c25239c`) and we customized it to our needs, integrated our layers of analysis, and tweaked the docker container. The specific changes to the initial Google P0 repository are documented in the file `functionsimsearch.patch`.


## Part 1
Before running the IDA plugin, follow the list of requirements from the IDA_scripts [README](../../../IDA_scripts/README.md#requirements).

- **Input**: the JSON file with the selected functions (`-j`), the output directory (`-o`), and (`-c`) to use Capstone to disassemble.
- **Output**: one JSON file per IDB

**Note**: the path of the IDB files in the JSON in input **must be relative** to the `binary_function_similarity` directory. The Python3 script converts the relative path into a full path to correctly load the IDB in IDA Pro.

Example: run the plugins over the functions selected for the Dataset-Vulnerability test (requires the IDBs in the `IDBs/Dataset-Vulnerability` directory)
```bash
cd IDA_fss
python3 cli_fss.py -j ../../../DBs/Dataset-Vulnerability/features/selected_Dataset-Vulnerability.json -o fss_Dataset-Vulnerability -c
```

Run unit tests:
```bash
python3 -m unittest test_fss.py

# optional - test on multiple files
python3 -m unittest test_large_fss.py
```


## Part 2
- **Input**: a directory with JSONs obtained via the IDA_fss plugin
- **Output**: four CSVs, each of which containing the results for one of the specific four tested configurations

Example input: [testdata/fss_jsons](testdata/fss_jsons).
Example output: [testdata/fss_csvs](testdata/fss_csvs).

### Tested configurations:
The following are the four configurations we tested. In each test we assign different weights to each feature.

| config | immediate | mnemonic | graphlet |
|--------|-----------|----------|----------|
|      1 |      4.00 |     0.05 |     1.00 |
|      2 |      0.00 |     0.00 |     1.00 |
|      3 |      0.00 |     1.00 |     1.00 |
|      4 |      1.00 |     1.00 |     1.00 |


### Build and run the Docker container
These are the concrete steps to run the analysis within the provided Docker container:

- Clone the functionsimsearch repository and apply the patch:
```bash
git clone https://github.com/googleprojectzero/functionsimsearch;
( cd functionsimsearch ; git checkout ec5d9e1224ff915b3dc9e7af19e21e110c25239c ; patch -s -p0 < ../functionsimsearch.patch );
cp fss_simhasher.py ./functionsimsearch/;
```

- Build the docker image:
```bash
docker build -t fss ./functionsimsearch
```

- Run the main script within the docker container: 
```bash
docker run --rm -it fss -v <full-path-to-the-input-jsons-dir>:/input -v <full-path-to-the-output-csvs-dir>:/output /fss_simhasher.py
```

Example (it creates four CSVs in `/tmp/fss_csvs`):
```bash
docker run --rm -v $(pwd)/testdata/fss_jsons:/input -v /tmp/fss_csvs:/output -it fss /fss_simhasher.py
```

- Run the script for the Dataset-2
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-2/features/fss_Dataset-2:/input -v $(pwd)/../../Results/FunctionSimSearch/Dataset-2:/output -it fss /fss_simhasher.py
```

## Copyright information about FunctionSimSearch

[FunctionSimSearch](https://github.com/googleprojectzero/functionsimsearch) is released under Apache License 2.0.

[IDA_fss.py](IDA_fss/IDA_fss.py) includes part of the code from https://github.com/williballenthin/python-idb/ and https://github.com/googleprojectzero/functionsimsearch which are licensed under Apache License 2.0.

