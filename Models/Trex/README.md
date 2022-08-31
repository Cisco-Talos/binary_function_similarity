# Trex

The code is constituted by two components: the first one takes as input the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) data and it produces as output a number of intermediate results. Those are then taken as input by the second part, which implements the machine learning component.

## Part 1
The first part of the tool is implemented in a Python3 script called [`generate_function_traces.py`](Preprocessing/generate_function_traces.py). We also provide a [Docker](Preprocessing/Dockerfile) container with the required dependencies.

The **input** of `generate_function_traces.py` is a folder with the JSON files extracted via the ACFG disasm IDA plugin:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-the-features-for-each-dataset).
- To extract the features for a new set of binaries, run the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm).

The script will produce the following **output**:
- A JSON file called `trex_traces.json` that contains the traces that are used in input by the Trex model

### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build Preprocessing/ -t trex-preprocessing
```

2. Run the the script within the docker container:
```bash
docker run --rm -v <path_to_the_acfg_disasm_dir>:/input -v <path_to_the_output_dir>:/output -it trex-preprocessing /code/generate_function_traces.py -i /input -o /output/
```

You can see all the command line options using:
```bash
docker run --rm -it trex-preprocessing /code/generate_function_traces.py --help
```

---

Example: run the `generate_function_traces.py` on the Dataset-Vulnerability:
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-Vulnerability/features/acfg_disasm_Dataset-Vulnerability:/input -v $(pwd)/Preprocessing/:/output -it trex-preprocessing /code/generate_function_traces.py -i /input -o /output/Dataset-Vulnerability-trex
```

---

Run unittest:
```bash
docker run --rm -v $(pwd)/Preprocessing/testdata/:/input -v $(pwd)/Preprocessing/testdata/trex_temp:/output -it trex-preprocessing /bin/bash -c "( cd /code && python3 -m unittest test_generate_function_traces.py )"
```

## Part 2

The machine learning component is implemented in a script called [`trex_inference.py`](NeuralNetwork/trex_inference.py). We also provide a [Docker](NeuralNetwork/Dockerfile) container with the required dependencies.

The script takes in **input**:
- The CSV file with the function pairs to compare. For the [Datasets](../../DBs) we have released, the function pairs are located in the `pairs` folder (example [here](../../DBs/Dataset-2/pairs))
- The JSON file with the function traces produced in output by the [`generate_function_traces.py`](Preprocessing/generate_function_traces.py) script
- The directory with the trained model ([link](https://drive.google.com/file/d/192jqfxotA9IyYa12sM82iklIEc3jVnwC/view?usp=sharing) to Google Drive)
- The folder with binarized data from the pre-training phase ([link](https://drive.google.com/file/d/1OnERQwIZnepvlFxa4InRNz_zOyQu-jix/view?usp=sharing) to Google Drive).

The script produces in **output**:
- A copy of the CSV file in input (called `{original_name}.trex_out.csv`) with an additional `cs` column that contains the cosine similarity between the function pairs.

### Instructions with Docker
The following are the concrete steps to run the Trex inference within the provided Docker container:
1. Build the docker image: 
```bash
docker build NeuralNetwork/ -t trex-inference
```

2. Run the inference script:
```bash
docker run --rm -v <path_to_the_function_pairs_folder>:/pairs -v <path_to_the_trex_traces_folder>:/traces -v <path_to_the_output_folder>:/output -it trex-inference conda run --no-capture-output -n trex python3 trex_inference.py --input-pairs /pairs/<name_of_csv_file> --input-traces /traces/trex_traces.json --model-checkpoint-dir checkpoints/similarity/ --data-bin-dir data-bin-sim/similarity/ --output-dir /output/<name_of_output_dir>
```

You can see all the command line options using:
```bash
docker run --rm -it trex-inference conda run --no-capture-output -n trex python3 trex_inference.py --help
```

---

Example:
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-Vulnerability/pairs/:/pairs -v $(pwd)/Preprocessing/Dataset-Vulnerability-trex/:/traces -v $(pwd)/NeuralNetwork/:/output -it trex-inference conda run --no-capture-output -n trex python3 trex_inference.py --input-pairs /pairs/pairs_testing_Dataset-Vulnerability.csv --input-traces /traces/trex_traces.json --model-checkpoint-dir checkpoints/similarity/ --data-bin-dir data-bin-sim/similarity/ --output-dir /output/Dataset-Vulnerability-trex
```

## How to use Trex on a new dataset of functions

The following are the main steps that are needed to run the Trex model on a new dataset of functions.

### Training

Our implementation only covers the inference part of the model. The official repository of [Trex](https://github.com/CUMLSec/trex) includes additional information on how to run the *pre-training* and *training* of the neural network.

### Validation and testing

1. Create a CSV file with the pairs of functions selected for validation and testing. Example [here](../../DBs/Dataset-2/pairs). (`idb_path_1`, `fva_1`) and (`idb_path_2`, `fva_2`) are the "primary keys".
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). `idb_path_1` and `idb_path_2` for the selected functions must be valid paths to the IDBs file to run the IDA plugin correctly.
3. Run the [`generate_function_traces.py`](Preprocessing/generate_function_traces.py) script following the instructions in [Part 1](#part-1).
4. Run the [`trex_inference.py`](NeuralNetwork/trex_inference.py) script following the instructions in [Part 2](#part-2).

## Additional notes

- The model was originally trained on four architectures (x86, x64, ARM 32 bit, and MIPS 32 bit), four optimization levels (O0, O1, O2, O3) and one compiler version (GCC-7.5). Also, the pre-training phase requires an emulation component that only supports those architectures. Due to these limitations, we only tested the Trex model on [Dataset-2](../../DBs/Dataset-2) and [Dataset-Vulnerability](../../DBs/Dataset-Vulnerability), which are a subset of the [binaries](https://github.com/CUMLSec/trex#dataset) that were released by the Trex authors.
- The Trex model is faster when running on a GPU, however this is not supported in the [Dockerfile](NeuralNetwork/Dockerfile) that we release.


## Copyright information about Trex

The original code of [Trex](https://github.com/CUMLSec/trex) is released under MIT license.