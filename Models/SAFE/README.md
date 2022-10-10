# SAFE

The SAFE tool is constituted by three components. The first is used to create a vocabulary of assembly instructions and to pretrain the instruction embeddings. The second tool takes as input the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) data and produces as output a number of intermediate results. Those are then taken as input by the third part, which implements the machine learning component.

## Part 1

The first part of the SAFE tool is implemented in a Python3 script called [`safe_pretraining.py`](Pretraining/safe_pretraining.py). We also provide a [Docker](Pretraining/Dockerfile) container with the required dependencies.

The `safe_pretraining.py` script is designed to create a vocabulary of assembly instructions and to pretrain the instruction embeddings using the Word2Vec model (skip-gram). This step is **only required** once for the model training: at inference time the model uses the fixed vocabulary of instructions and their corresponding embeddings.

The **input** is a folder with the JSON files extracted via the ACFG disasm IDA plugin:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-the-features-for-each-dataset).
- To extract the features for a new set of binaries, run the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm).

The script will produce the following **output**:
- A file called  `embeddings.npy` which contains the matrix of instruction embeddings, with one embedding for each selected instruction.
- A file called  `ins2id.json` with maps the selected instruction to an index in the matrix of instruction embeddings.
- A file called  `ins2count.json` with the number of occurrences of each instruction in the training corpus. For debug only.
- A file called  `pretraining.txt` which contains the training corpus to train the instruction embeddings. For debug only.
- A file called  `pretraining_unk.txt` which contains training corpus without infrequent tokens. For debug only.

### Instructions with Docker
The following are the concrete steps to run the pretrain with the provided Docker container:
1. Build the docker image: 
```bash
docker build --no-cache Pretraining/ -t safe-pretraining
```

2. Run the main script within the docker container:
```bash
docker run --rm -v <path_to_the_acfg_disasm_dir>:/input -v <path_to_the_safe_pretraining_output_dir>:/output -it safe-pretraining /code/safe_pretraining.py -i /input -o /output
```

You can see all options of the `safe_pretraining.py` command with:
```bash
docker run --rm -it safe-pretraining /code/safe_pretraining.py --help
```
---

Example: run `safe_pretraining.py` on the Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-1/features/training/acfg_disasm_Dataset-1_training:/input -v $(pwd)/Pretraining/:/output -it safe-pretraining /code/safe_pretraining.py -i /input -o /output/Dataset-1_training
```

## Part 2

The second part of the SAFE tool is implemented in a Python3 script called [`safe_preprocessing.py`](Preprocessing/safe_preprocessing.py). We also provide a [Docker](Preprocessing/Dockerfile) container with the required dependencies.

The **input** is:
* A folder with the JSON files extracted via the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) IDA plugin. More information in [Part 1](#part-1).
* The `ins2id.json` file produced by the `safe_pretraining.py` tool in [Part 1](#part-1).
* The maximum number of instructions per function (default: 250).

The script will produce the following **output**:
* A JSON file named `instructions_embeddings_list_{max_instructions}.json`. Each function is modeled as a list of integers, where each number is the index of the corresponding assembly instruction in the matrix of embeddings.
* A `log_coverage.txt` file that logs functions with more than half out-of-vocabulary instructions. For debug only.

### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build --no-cache Preprocessing/ -t safe-preprocessing
```

2. Run the main script within the docker container: 
```bash
docker run --rm -v <path_to_the_acfg_disasm_dir>:/input -v <path_to_the_safe_pretraining_output_dir>:/instruction_embeddings -v <path_to_the_safe_preprocessing_output_dir>:/output -it safe-preprocessing /code/safe_preprocessing.py -i /input -o /output
```

You can see all options of the `safe_preprocessing.py` command with:
```bash
docker run --rm -it safe-preprocessing /code/safe_preprocessing.py --help
```

---

* Example: run `safe_preprocessing.py` on the Dataset-1_training
```bash
docker run --rm  -v $(pwd)/../../DBs/Dataset-1/features/training/acfg_disasm_Dataset-1_training:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/output -it safe-preprocessing /code/safe_preprocessing.py -i /input -o /output/Dataset-1_training
```

* Example: run `safe_preprocessing.py` on the Dataset-1_validation
```bash
docker run --rm  -v $(pwd)/../../DBs/Dataset-1/features/validation/acfg_disasm_Dataset-1_validation:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/output -it safe-preprocessing /code/safe_preprocessing.py -i /input -o /output/Dataset-1_validation
```

* Example: run `safe_preprocessing.py` on the Dataset-1_testing
```bash
docker run --rm  -v $(pwd)/../../DBs/Dataset-1/features/testing/acfg_disasm_Dataset-1_testing:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/output -it safe-preprocessing /code/safe_preprocessing.py -i /input -o /output/Dataset-1_testing
```

* Example: run `safe_preprocessing.py` on the Dataset-2
```bash
docker run --rm  -v $(pwd)/../../DBs/Dataset-2/features/acfg_disasm_Dataset-2:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/output -it safe-preprocessing /code/safe_preprocessing.py -i /input -o /output/Dataset-2
```

* Example: run `safe_preprocessing.py` on the Dataset-Vulnerability
```bash
docker run --rm  -v $(pwd)/../../DBs/Dataset-Vulnerability/features/acfg_disasm_Dataset-Vulnerability:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/output -it safe-preprocessing /code/safe_preprocessing.py -i /input -o /output/Dataset-Vulnerability
```

---

Run unittest:
```bash
docker run --rm -v $(pwd)/Preprocessing/testdata/:/input -v $(pwd)/Pretraining/instruction_embeddings:/instruction_embeddings -v $(pwd)/Preprocessing/testdata/safe_intermediate:/output -it safe-preprocessing /bin/bash -c "( cd /code && python3 -m unittest test_safe_preprocessing.py )"
```

## Part 3

The third part implements the machine learning component of SAFE. We also provide a [Docker](NeuralNetwork/Dockerfile) container with TensorFlow 1.14 and the other required dependencies.

The neural network model takes in **input**:
- The CSV files with the functions *to train*, or the pair of functions *to validate and test* the model. These files are already available for the [Datasets](../../DBs) we have released. The path of these files is hard coded in the [`config.py`](NeuralNetwork/core/config.py) file, based on the dataset type
- The embeddings matrix `embeddings.npy` from the output of [Part 1](#part-1)
- The JSON file `instructions_embeddings_list_250.json` from the output of [Part 2](#part-2)
- The model [checkpoint](NeuralNetwork/model_checkpoint) (only if the model is used in inference mode, i.e., during validation and testing).

The model will produce the following **output**:
- A set of CSV files with the similarity (column `sim`) for the functions selected for validation and testing
- A `config.json` file with the configuration used to run the test. This includes the parameters and the path of the CSV and JSON files in input. This file is useful for debugging and tracking different experiments
- A `safe.log` file with the logs from the neural network. To improve logging, use the `--debug` (`-d`) option
- The model checkpoint (only if the model is trained).

### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build --no-cache NeuralNetwork/ -t safe-neuralnetwork
```

2. Run the SAFE neural network within the Docker container:
```bash
docker run --rm 
    -v $(pwd)/../../DBs:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/preprocessing  -v $(pwd)/NeuralNetwork/:/output  -it safe-neuralnetwork /code/safe_nn.py (--train | --validate | --test) [--num_epochs 5] --dataset {one,two,vuln} -c /code/model_checkpoint_$(date +'%Y-%m-%d') -o /output/Dataset-x
```

The `safe_nn.py` program uses the path to the `/input` folder to locate the necessary files to run the training, validation and testing for the Dataset-1, Dataset-2 and Dataset-Vulnerability. The program uses the default paths to locate the `embeddings.npy` and `instructions_embeddings_list_250.json` files under the `/instruction_embeddings` and `/preprocessing` folders. Different paths can be specified using different command line options.

Use the `--dataset` option to select the corresponding dataset: `--dataset one`, `--dataset two` or `--dataset vuln`.

Use the `--random_embeddings` option to replace the pretrained embeddings with random ones.

Use the `--trainable_embeddings` option to train the embedding with the rest of the neural network.

* You can see all options of the `safe_nn.py` command with:
```bash
docker run --rm -it safe-neuralnetwork /code/safe_nn.py --help
```

---

* Example: run the training on the Dataset-1
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/preprocessing -v $(pwd)/NeuralNetwork/:/output -it safe-neuralnetwork /code/safe_nn.py --train --num_epochs 5 --dataset one -c /output/model_checkpoint_$(date +'%Y-%m-%d') -o /output/Dataset-1_training
```

The new trained model will be saved in `$(pwd)/NeuralNetwork/model_checkpoint_$(date +'%Y-%m-%d')`. Use the `--restore` option to continue the training from an existing checkpoint.

* Example: run the validation on Dataset-1 using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/preprocessing -v $(pwd)/NeuralNetwork/:/output -it safe-neuralnetwork /code/safe_nn.py --validate --dataset one -c /code/model_checkpoint -o /output/Dataset-1_validation
```

* Example: run the testing on Dataset-1 using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/preprocessing -v $(pwd)/NeuralNetwork/:/output -it safe-neuralnetwork /code/safe_nn.py --test --dataset one -c /code/model_checkpoint -o /output/Dataset-1_testing
```

* Example: run the testing on Dataset-2 using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/preprocessing -v $(pwd)/NeuralNetwork/:/output -it safe-neuralnetwork /code/safe_nn.py --test --dataset two -c /code/model_checkpoint -o /output/Dataset-2_testing
```

* Example: run the testing on Dataset-Vulnerability using the [model_checkpoint](NeuralNetwork/model_checkpoint) that we trained on Dataset-1:
```bash
docker run --rm -v $(pwd)/../../DBs:/input -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings -v $(pwd)/Preprocessing:/preprocessing -v $(pwd)/NeuralNetwork/:/output -it safe-neuralnetwork /code/safe_nn.py --test --dataset vuln -c /code/model_checkpoint -o /output/Dataset-Vulnerability_testing
```


## How to use SAFE on a new dataset of functions

The following are the main steps that are needed to run SAFE on a new dataset of functions.

### Training

1. Create a CSV file with the selected functions for training. Example [here](../../DBs/Dataset-1/training_Dataset-1.csv). `idb_path` and `fva` are the "primary keys" used to uniquely identify a function. The only requirement is to have the same function (i.e., the same function name) to be compiled under different settings (e.g., compilers, architectures, optimizations). The more the variants for each function, the better the model can generalize.
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). The `idb_path` for the selected functions must be a valid path to an IDB file to run the IDA plugin correctly.
3. (Optional) Run the SAFE pretraining tool to pretrain the instruction embedding following the instructions in [Part 1](#part-1).
3. Run the SAFE preprocessing tool following the instructions in [Part 2](#part-2).
4. Run the SAFE neural network in training mode (`--train`) following the instructions in [Part 3](#part-3).

### Validation and testing

1. Create a CSV file with the pairs of functions selected for validation and testing. Example [here](../../DBs/Dataset-1/pairs). (`idb_path_1`, `fva_1`) and (`idb_path_2`, `fva_2`) are the "primary keys".
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). `idb_path_1` and `idb_path_2` for the selected functions must be valid paths to the IDBs file to run the IDA plugin correctly.
3. Run the SAFE preprocessing tool following the instructions in [Part 2](#part-2).
4. Run the SAFE neural network in testing mode (`--test`) following the instructions in [Part 3](#part-3). 

## Additional notes

* The SAFE neural network consider only the first N (e.g., 150) instructions in a function. This limits the efficacy of the approach on larger functions.
* The model [checkpoint](NeuralNetwork/model_checkpoint) we provide was trained using the functions of [Dataset-1](../../DBs/Dataset-1/), which have been compiled for Linux using three architectures (x86-64, ARM 32/64 and MIPS 32/64), five optimizations, and two  compilers (GCC and CLANG). Do not use the model to infer the similarity for functions compiled in different settings (e.g., for Windows), but retrain it following the instructions above.


## Copyright information about the SAFE Neural Network model

The [neural network](NeuralNetwork) implementation includes part of the code from https://github.com/gadiluna/SAFE which is licensed under GPL-3.0.
