# GGSNN-GMN

This folder contains the implementation of the GGSNN and GMN models from DeepMind. The tool is constituted by two components. The first one takes as input the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) data and it produces as output a number of intermediate results. Those are then taken as input by the second part, which implements the machine learning component.

## Part 1

The first part of the tool is implemented in a Python3 script called [`gnn_preprocessing.py`](Preprocessing/gnn_preprocessing.py). We also provide a [Docker](Preprocessing/Dockerfile) container with the required dependencies.

The **input** is a folder with the JSON files extracted via the ACFG disasm IDA plugin:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-the-features-for-each-dataset).
- To extract the features for a new set of binaries, run the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm).
- A JSON file `opcodes_dict.json` that maps the selected opcodes to their (frequency) ranking in the training dataset. 

The script will produce the following **output**:
- A JSON file `opcodes_dict.json` that maps the selected opcodes to their (frequency) ranking in the training dataset. (Only if the script is launched in `--training` mode.)
- A JSON file `graph_func_dict_opc_{}.json` with the selected intermediate features.

### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build --no-cache Preprocessing/ -t gnn-preprocessing
```

2. Run the main script within the docker container: 
```bash
docker run --rm \
    -v <path_to_the_acfg_disasm_dir>:/input \
    -v <path_to_the_training_data>:/training_data \
    -v <path_to_the_output_dir>:/output \
    -it gnn-preprocessing /code/gnn_preprocessing.py -i /input [--training] -o /output
```

You can see all options of the `gnn_preprocessing.py` command with:
```bash
docker run --rm -it gnn-preprocessing /code/gnn_preprocessing.py --help
```

---

* Example: run `gnn_preprocessing.py` in *training mode* on the Dataset-1_training:
```bash
docker run --rm \
    -v $(pwd)/../../DBs/Dataset-1/features/training/acfg_disasm_Dataset-1_training:/input \
    -v $(pwd)/Preprocessing/Dataset-1_training:/output \
    -it gnn-preprocessing /code/gnn_preprocessing.py -i /input --training -o /output
```

* Example: run `gnn_preprocessing.py` on the Dataset-1_validation:
```bash
docker run --rm \
    -v $(pwd)/../../DBs/Dataset-1/features/validation/acfg_disasm_Dataset-1_validation:/input \
    -v $(pwd)/Preprocessing/Dataset-1_training:/training_data \
    -v $(pwd)/Preprocessing/Dataset-1_validation:/output \
    -it gnn-preprocessing /code/gnn_preprocessing.py -i /input -d /training_data/opcodes_dict.json -o /output
```

* Example: run `gnn_preprocessing.py` on the Dataset-1_testing:
```bash
docker run --rm \
    -v $(pwd)/../../DBs/Dataset-1/features/testing/acfg_disasm_Dataset-1_testing:/input \
    -v $(pwd)/Preprocessing/Dataset-1_training:/training_data \
    -v $(pwd)/Preprocessing/Dataset-1_testing:/output \
    -it gnn-preprocessing /code/gnn_preprocessing.py -i /input -d /training_data/opcodes_dict.json -o /output
```

* Example: run `gnn_preprocessing.py` on the Dataset-2:
```bash
docker run --rm \
    -v $(pwd)/../../DBs/Dataset-2/features/acfg_disasm_Dataset-2:/input \
    -v $(pwd)/Preprocessing/Dataset-1_training:/training_data \
    -v $(pwd)/Preprocessing/Dataset-2:/output \
    -it gnn-preprocessing /code/gnn_preprocessing.py -i /input -d /training_data/opcodes_dict.json -o /output
```

* Example: run `gnn_preprocessing.py` on the Dataset-Vulnerability
```bash
docker run --rm \
    -v $(pwd)/../../DBs/Dataset-Vulnerability/features/acfg_disasm_Dataset-Vulnerability:/input \
    -v $(pwd)/Preprocessing/Dataset-1_training:/training_data \
    -v $(pwd)/Preprocessing/Dataset-Vulnerability:/output \
    -it gnn-preprocessing /code/gnn_preprocessing.py -i /input -d /training_data/opcodes_dict.json -o /output
```

---

Run unittest:
```bash
docker run --rm \
    -v $(pwd)/Preprocessing/testdata/:/input \
    -v $(pwd)/Preprocessing/testdata/gnn_intermediate:/output \
    -it gnn-preprocessing /bin/bash -c "( cd /code && python3 -m unittest test_gnn_preprocessing.py )"
```

## Part 2

The second part implements the machine learning component. We also provide a [Docker](NeuralNetwork/Dockerfile) container with TensorFlow 1.14 and the other required dependencies.

The neural network model takes in **input**:
- The CSV files with the functions *to train*, or the pair of functions *to validate and test* the model. These files are already available for the [Datasets](../../DBs) we have released. The path of these files is hardcoded in the [`config.py`](NeuralNetwork/core/config.py) file, based on the dataset type.
- The `graph_func_dict_opc_{}.json` file from [Part 1](#part-1).
- The model [checkpoint](NeuralNetwork/model_checkpoint_GGSNN_pair) (only if the model is used in inference mode, i.e., during validation and testing).

The model will produce the following **output**:
- A set of CSV files with the similarity (column `sim`) for the functions selected for validation and testing
- A `config.json` file with the configuration used to run the test. This includes the parameters and the path of the CSV and JSON files in input. This file is useful for debugging and tracking different experiments.
- A `gnn.log` file with the logs from the neural network. To improve logging, use the `--debug` (`-d`) option.
- The model checkpoint (only if the model is trained).

### Instructions with Docker
The following are the concrete steps to run the the neural network using our Docker container:
1. Build the docker image: 
```bash
docker build --no-cache NeuralNetwork/ -t gnn-neuralnetwork
```

2. Run the neural network within the Docker container:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-neuralnetwork /code/gnn.py (--train | --validate | --test) [--num_epochs 10] \
        --model_type {embedding, matching} --training_mode {pair,triplet} \
        --features_type {opc,nofeatures} --dataset {one,two,vuln} \
        -c /code/model_checkpoint \
        -o /output/Dataset-x
```

* You can see all options of the `gnn.py` command with:
```bash
docker run --rm -it gnn-neuralnetwork /code/gnn.py --help 
```

---

* Example: run the training on the Dataset-1 for the `GGSNN` model (`embedding`) with `opc` features in `pair` mode
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/NeuralNetwork:/output \
    -v $(pwd)/Preprocessing:/preprocessing \
    -it gnn-neuralnetwork /code/gnn.py --train --num_epochs 10 \
        --model_type embedding --training_mode pair \
        --features_type opc --dataset one \
        -c /output/model_checkpoint_$(date +'%Y-%m-%d') \
        -o /output/Dataset-1_training_GGSNN_opc_pair
```

The new trained model will be saved in `$(pwd)/NeuralNetwork/model_checkpoint_$(date +'%Y-%m-%d')`. Use the `--restore` option to continue the training from an existing checkpoint.

* Example: run the training on the Dataset-1 for the `GGSNN` model (`embedding`) with `nofeatures` in `pair` mode
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/NeuralNetwork:/output \
    -v $(pwd)/Preprocessing:/preprocessing \
    -it gnn-neuralnetwork /code/gnn.py --train --num_epochs 10 \
        --model_type embedding --training_mode pair \
        --features_type nofeatures --dataset one \
        -c /output/model_checkpoint_$(date +'%Y-%m-%d') \
        -o /output/Dataset-1_training_GGSNN_nofeatures_pair
```

* Example: run the training on the Dataset-1 for the `GMN` model (`matching`) with `opc` features in `pair` mode
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/NeuralNetwork:/output \
    -v $(pwd)/Preprocessing:/preprocessing \
    -it gnn-neuralnetwork /code/gnn.py --train --num_epochs 16 \
        --model_type matching --training_mode pair \
        --features_type opc --dataset one \
        -c /output/model_checkpoint_$(date +'%Y-%m-%d') \
        -o /output/Dataset-1_training_GMN_opc_pair
```

* Example: run the validation on Dataset-1 using the [model_checkpoint](NeuralNetwork/model_checkpoint_GGSNN_pair) that we trained on Dataset-1:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/NeuralNetwork/:/output \
    -v $(pwd)/Preprocessing:/preprocessing \
    -it gnn-neuralnetwork /code/gnn.py --validate \
        --model_type embedding --training_mode pair \
        --features_type opc --dataset one \
        -c /code/model_checkpoint_GGSNN_pair \
        -o /output/Dataset-1_validation
```

* Example: run the testing on Dataset-1 using the [model_checkpoint](NeuralNetwork/model_checkpoint_GGSNN_pair) that we trained on Dataset-1:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/NeuralNetwork/:/output \
    -v $(pwd)/Preprocessing:/preprocessing \
    -it gnn-neuralnetwork /code/gnn.py --test \
        --model_type embedding --training_mode pair \
        --features_type opc --dataset one  \
        -c /code/model_checkpoint_GGSNN_pair \
        -o /output/Dataset-1_testing
```

## How to run the models on a new dataset of functions

The following are the main steps that are needed to run the models on a new dataset of functions.

### Training

1. Create a CSV file with the selected functions for training. Example [here](../../DBs/Dataset-1/training_Dataset-1.csv). `idb_path` and `fva` are the "primary keys" used to uniquely identify a function. The only requirement is to have the same function (i.e., the same function name) to be compiled under different settings (e.g., compilers, architectures, optimizations). The more the variants for each function, the better the model can generalize.
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). The `idb_path` for the selected functions must be a valid path to an IDB file to run the IDA plugin correctly.
3. Run the GGSNN/GMN preprocessing tool following the instructions in [Part 1](#part-1).
4. Run the GGSNN/GMN neural network in training mode (`--train`) following the instructions in [Part 2](#part-2).

### Validation and testing

1. Create a CSV file with the pairs of functions selected for validation and testing. Example [here](../../DBs/Dataset-1/pairs). (`idb_path_1`, `fva_1`) and (`idb_path_2`, `fva_2`) are the "primary keys".
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). `idb_path_1` and `idb_path_2` for the selected functions must be valid paths to the IDBs file to run the IDA plugin correctly.
3. Run the GGSNN/GMN preprocessing tool following the instructions in [Part 1](#part-1).
4. Run the GGSNN/GMN neural network in testing mode (`--test`) following the instructions in [Part 2](#part-2). 

## Additional notes

* The GMN neural network **requires two functions in input to compute their similarity**. This limits the scalability of the approach because the model does not translate the function into an embedding representation.
* The model [checkpoint](NeuralNetwork/model_checkpoint_GGSNN_pair) we provide was trained using the functions of [Dataset-1](../../DBs/Dataset-1/), which have been compiled for Linux using three architectures (x86-64, ARM 32/64 and MIPS 32/64), five optimizations, and two  compilers (GCC and CLANG). Do not use the model to infer the similarity for functions compiled in different settings (e.g., for Windows), but retrain it following the instructions above.
* The implementation allows to select different types of loss functions, features and training modes (pair or triplet). More information in the [gnn.py](NeuralNetwork/gnn.py) and [`config.py`](NeuralNetwork/core/config.py) files.

## Copyright information

The [NeuralNetwork](NeuralNetwork) implementation includes part of the code from https://github.com/deepmind/deepmind-research/blob/master/graph_matching_networks/graph_matching_networks.ipynb which is licensed under Apache License 2.0.

