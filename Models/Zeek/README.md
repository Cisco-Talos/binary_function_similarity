# Zeek

The Zeek tool is constituted by two components. The first one takes as input the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) data and it produces as output a number of intermediate results. Those are then taken as input by the second part, which implements the machine learning component.

## Part 1

The first part of the Zeek tool is implemented in a Python3 script called [`zeek.py`](Preprocessing/zeek.py). We also provide a [Docker](Preprocessing/Dockerfile) container with the required dependencies.

The **input** is a folder with the JSON files extracted via the ACFG disasm IDA plugin:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-the-features-for-each-dataset).
- To extract the features for a new set of binaries, run the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm).

The script will produce the following **output**:
- a directory called `logs` which contains the logs of the analysis: these are useful only to monitor the analysis progress and for debugging
- a directory called `jsons` with one JSON file for each ACFG disasm JSON in input, containing the intermediate results
- a file called `zeek.json` which combines all the JSON files of the `jsons` directory in one. This is *the input* to the second part of the Zeek tool, the machine learning part.

### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build --no-cache Preprocessing/ -t zeek
```

2. Run the main script within the docker container: 
```bash
docker run --rm --name zeek_preprocessing -v <path_to_the_acfg_disasm_dir>:/input -v <path_to_the_zeek_output_dir>:/output -it zeek /code/zeek.py process /input /output [--workers-num 5]
```

You can see all options of the `zeek.py process` command with:
```bash
docker run --rm -it zeek /code/zeek.py process --help
```

For debugging only (to be run within the docker container):
```bash
docker exec -it zeek_preprocessing /bin/bash
/code/zeek.py stats /input /output
```
This command shows stats on the "current" status, so you can run during or after the analysis has completed.

---

Example: run `zeek.py process` on the Dataset-Vulnerability
```bash
docker run --rm --name zeek_preprocessing -v $(pwd)/../../DBs/Dataset-Vulnerability/features/acfg_disasm_Dataset-Vulnerability:/input -v $(pwd)/Preprocessing/zeek_intermediate/Dataset-Vulnerability:/output -it zeek /code/zeek.py process /input /output --workers-num 10
```

Note: the path to the output directory `zeek_intermediate/Dataset-Vulnerability` is recursively created by the `zeek.py` script.

---

Run unittest:
```bash
docker run --rm -v $(pwd)/Preprocessing/testdata/:/input -v $(pwd)/Preprocessing/testdata/zeek_intermediate:/output -it zeek /bin/bash -c "( cd /code && python3 -m unittest test_zeek.py )"
```

### Notes on the output format of the first part

The `zeek.json` output file contains only the minimum required intermediate data, that is **the hashes for each analyzed function**.

Each JSON file in the `jsons` directory contains the same information as in `zeek.json`, plus additional information which may be useful for debugging. In particular, these JSONs include so-called "raw hashes": raw hashes are the MD5 of the expression tree of each strand extracted from each VEX block (note on terminology: a binary contains one or more functions, a function contains one or more VEX blocks, a VEX block contains one or more strands. We calculate one hash for each strand). These raw hashes are then truncated to 10 bits, and then merged at the function level. These "merged hashes" constituted the (non-raw) "hashes" included in `zeek.json`.


## Part 2

The second part implements the machine learning component of Zeek. We also provide a [Docker](Preprocessing/Dockerfile) container with TensorFlow 1.14 and the other required dependencies.

The neural network model takes in **input**:
- The CSV files with the functions *to train*, or the pair of functions *to validate and test* the model. These files are already available for the [Datasets](../../DBs) we have released. The path of these files is hardcoded in the [`config.py`](NeuralNetwork/core/config.py) file, based on the dataset type.
- The `zeek.json` files that come from the output of [Part 1](#part-1).
- The model [checkpoint](NeuralNetwork/model_checkpoint) (only if the model is used in inference mode, i.e., during validation and testing).

The model will produce the following **output**:
- A set of CSV files with the similarity (colum `sim`) for the functions selected for validation and testing
- A `config.json` file with the configuration used to run the test. This includes the parameters and the path of the CSV and JSON files in input. This file is useful for debugging and tracking different experiments.
- A `zeek.log` file with the logs from the neural network. To improve logging, use the `--debug` (`-d`) option.
- The model checkpoint (only if the model is trained).

### Instructions with Docker
The following are the concrete steps to run the the neural network using our Docker container:
1. Build the docker image: 
```bash
docker build --no-cache NeuralNetwork/ -t zeekneuralnetwork
```

2. Run the Zeek neural network within the Docker container:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/NeuralNetwork/:/output -it zeekneuralnetwork /code/zeek_nn.py [--train] [--test] [--num_epochs 10] [-c /code/model_checkpoint] [--dataset one]  -o /output/Dataset-x
```

The `zeek_nn.py` program uses the path to the `/input` folder to locate the necessary files to run the training, validation and testing for the Dataset-1, Dataset-2 and Dataset-Vulnerability. In particular, the `zeek.json` file that is extracted in [Part 1](#part-1) of the README is automatically downloaded in the `features` directory for the [Datasets](../../DBs) we have released (more information in the [README](../../DBs/#download-the-features-for-each-dataset)). For simplicity, the path of the required files in input is hardcoded in the [`config.py`](NeuralNetwork/core/config.py) file (e.g., for the [Dataset-1](NeuralNetwork/core/config.py#L52)). Use the `--dataset` option to select the corresponding dataset: `--dataset one`, `--dataset two` or `--dataset vuln`.


* You can see all options of the `zeek_nn.py` command with:
```bash
docker run --rm -it zeekneuralnetwork /code/zeek_nn.py --help 
```

---

* Example: run the training on the Dataset-1
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/NeuralNetwork:/output -it zeekneuralnetwork /code/zeek_nn.py --train --num_epochs 10 -c /code/model_checkpoint_$(date +'%Y-%m-%d') --dataset one -o /output/Dataset-1_training
```
The new trained model will be saved in `model_checkpoint_$(date +'%Y-%m-%d')`. Use the `--restore` option to continue the training of an existing checkpoint.


* Example: run the testing on Dataset-1 using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/NeuralNetwork/:/output -it zeekneuralnetwork /code/zeek_nn.py --test --dataset one -c /code/model_checkpoint -o /output/Dataset-1_testing
```

* Example: run the testing on Dataset-2 using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/NeuralNetwork/:/output -it zeekneuralnetwork /code/zeek_nn.py --test --dataset two -c /code/model_checkpoint -o /output/Dataset-2_testing
```

* Example: run the testing on Dataset-Vulnerability using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/NeuralNetwork/:/output -it zeekneuralnetwork /code/zeek_nn.py --test --dataset vuln -c /code/model_checkpoint -o /output/Dataset-Vulnerability
```

## How to use Zeek on a new dataset of functions

The following are the main steps that are needed to run Zeek on a new dataset of functions.

### Training

1. Create a CSV file with the selected functions for training. Example [here](../../DBs/Dataset-1/training_Dataset-1.csv). `idb_path` and `fva` are the "primary keys" used to uniquely identify a function. The only requirement is to have the same function (i.e., the same function name) to be compiled under different settings (e.g., compilers, architectures, optimizations). The more the variants for each function, the better the model can generalize.
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). The `idb_path` for the selected functions must be a valid path to an IDB file to run the IDA plugin correctly.
3. Run the Zeek preprocessing tool following the instructions in [Part 1](#part-1).
4. Run the Zeek neural network in training mode (`--train`) following the instructions in [Part 2](#part-2).

### Validation and testing

1. Create a CSV file with the pairs of functions selected for validation and testing. Example [here](../../DBs/Dataset-1/pairs). (`idb_path_1`, `fva_1`) and (`idb_path_2`, `fva_2`) are the "primary keys".
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). `idb_path_1` and `idb_path_2` for the selected functions must be valid paths to the IDBs file to run the IDA plugin correctly.
3. Run the Zeek preprocessing tool following the instructions in [Part 1](#part-1).
4. Run the Zeek neural network in testing mode (`--test`) following the instructions in [Part 2](#part-2). 

## Additional notes

* The Zeek neural network **requires two functions in input to compute their similarity**. This limits the scalability of the approach because the model does not translate the function into an embedding representation.
* The model [checkpoint](NeuralNetwork/model_checkpoint) we provide was trained using the functions of [Dataset-1](../../DBs/Dataset-1/), which have been compiled for Linux using three architectures (x86-64, ARM 32/64 and MIPS 32/64), five optimizations, and two  compilers (GCC and CLANG). Do not use the model to infer the similarity for functions compiled in different settings (e.g., for Windows), but retrain it following the instructions above.

