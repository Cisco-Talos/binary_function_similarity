# GNN-s2v

This folder contains the implementation of the methods based on Graph Neural Network (GNN) and the Structure2vec (s2v) approach. The code is constituted by two components: the first one takes as input the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) or [ACFG features](../../IDA_scripts/#ida-acfg-features) data and it produces as output a number of intermediate results. Those are then taken as input by the second part, which implements the machine learning component.

## Download the model data

1. Activate the Python3 virtualenv
```bash
source ../../env/bin/activate
```

2. Download and unzip the model data in the corresponding folders:
```bash
python3 gdrive_model_download.py
```

The data will be unzipped in the following directories:
```bash
Pretraining/Dataset-1_training
NeuralNetwork/model_checkpoint_annotations_none_epoch5
NeuralNetwork/model_checkpoint_annotations_numerical_epoch5
```

## Part 1

The first part of the tool implements a preprocessing step in two Python3 scripts called [`digraph_instructions_embeddings.py`](Preprocessing/digraph_instructions_embeddings.py) and [`digraph_numerical_features.py`](Preprocessing/digraph_numerical_features.py). We also provide a [Docker](Preprocessing/Dockerfile) container with the required dependencies.

### Preprocessing for the model presented in "Investigating Graph Embedding Neural Networks with Unsupervised Features Extraction for Binary Analysis."

In order to extract the features required by this ML model, use the [`digraph_instructions_embeddings.py`](Preprocessing/digraph_instructions_embeddings.py) Python3 script.

The **input** of `digraph_instructions_embeddings.py` is a folder with the JSON files extracted via the [ACFG disasm](../../IDA_scripts/IDA_acfg_disasm) IDA plugin and the pretrained instruction embeddings:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-the-features-for-each-dataset)
- To extract the features for a new set of binaries, run the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm)
- In the [Pretraining](./Pretraining) folder, we provide the vocabulary of assembly instructions and the pretrained instruction embeddings. These are the same as in the [SAFE](../SAFE) model, and they have been pretrained over the training portion of [Dataset-1](../../DBs#dataset-1). Additional information can be found in the SAFE [README](../SAFE#part-1)
- By default `digraph_instructions_embeddings.py` selects the first 200 instructions for each basic block, however the number is configurable via command line.

The script will produce the following **output**:
- A file called `digraph_instructions_embeddings_{NUM_INSTRUCTIONS}.json` that contains the graph representation and the features for each selected function
- A log file called `log_coverage.txt` that provides information about the frequency of unknown instructions.

### Preprocessing for the model presented in "Neural network-based graph embedding for cross-platform binary code similarity detection."

In order to extract the features required by this ML model, use the [`digraph_numerical_features.py`](Preprocessing/digraph_numerical_features.py) Python3 script.

The **input** of `digraph_numerical_features.py` is a folder with the JSON files extracted via the [ACFG features](../../IDA_scripts/IDA_acfg_features) IDA plugin:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-features)
- To extract the features for a new set of binaries, run the ACFG features IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-features).

The script will produce the following **output**:
- A file called `digraph_numerical_features.json` that contains the graph representation and the features for each selected function.


### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build Preprocessing/ -t gnn-s2v-preprocessing
```

2. Run the two scripts within the docker container: 
```bash
docker run \
    --rm \
    -v <path_to_the_acfg_disasm_dir>:/input \
    -v <path_to_the_instruction_embeddings_dir>:/instruction_embeddings \
    -v <path_to_the_output_dir>:/output \
    -it gnn-s2v-preprocessing /code/digraph_instructions_embeddings.py \
        -i /input \
        -d /instruction_embeddings/ins2id.json \
        -o /output/
```

```bash
docker run \
    --rm \
    -v <path_to_the_acfg_features_dir>:/input \
    -v <path_to_the_output_dir>:/output \
    -it gnn-s2v-preprocessing /code/digraph_numerical_features.py \
        -i /input \
        -o /output
```

You can see all options of the two scripts with:
```bash
docker run --rm -it gnn-s2v-preprocessing /code/digraph_instructions_embeddings.py --help
```

```bash
docker run --rm -it gnn-s2v-preprocessing /code/digraph_numerical_features.py --help
```

---

Example: run the `digraph_instructions_embeddings.py` on the Dataset-Vulnerability:
```bash
docker run \
    --rm \
    -v $(pwd)/../../DBs/Dataset-Vulnerability/features/acfg_disasm_Dataset-Vulnerability:/input \
    -v $(pwd)/Pretraining/Dataset-1_training/:/instruction_embeddings \
    -v $(pwd)/Preprocessing/:/output \
    -it gnn-s2v-preprocessing /code/digraph_instructions_embeddings.py \
        -i /input \
        -d /instruction_embeddings/ins2id.json \
        -o /output/Dataset-Vulnerability/
```

Example: run the `digraph_numerical_features.py` on the Dataset-Vulnerability:
```bash
docker run \
    --rm \
    -v $(pwd)/../../DBs/Dataset-Vulnerability/features/acfg_features_Dataset-Vulnerability:/input \
    -v $(pwd)/Preprocessing/:/output \
    -it gnn-s2v-preprocessing /code/digraph_numerical_features.py \
        -i /input \
        -o /output/Dataset-Vulnerability/
```
---

Run unittest:
```bash
docker run \
    --rm  \
    -v $(pwd)/Preprocessing/testdata/:/input  \
    -v $(pwd)/Pretraining/Dataset-1_training/:/instruction_embeddings  \
    -v $(pwd)/Preprocessing/testdata/s2v_temp:/output  \
    -it gnn-s2v-preprocessing /bin/bash  \
        -c "( cd /code && python3 -m unittest test_digraph_instructions_embeddings.py )"
```

```bash
docker run \
    --rm  \
    -v $(pwd)/Preprocessing/testdata/:/input  \
    -v $(pwd)/Preprocessing/testdata/s2v_temp:/output  \
    -it gnn-s2v-preprocessing /bin/bash  \
        -c "( cd /code && python3 -m unittest test_digraph_numerical_features.py )"
```

## Part 2

The second part implements the machine learning component of the GNN-s2v approach. We also provide a [Docker](NeuralNetwork/Dockerfile) container with TensorFlow 1.14 and the other required dependencies.

The neural network model takes in **input**:
- The CSV files with the functions *to train*, or the pair of functions *to validate and test* the model. These files are already available for the [Datasets](../../DBs) we have released. The path of these files is hard coded in the [`config.py`](NeuralNetwork/core/config.py) file, based on the dataset type
- The embeddings matrix `embeddings.npy` with the pretrained instruction embeddings. This is the same as in the [SAFE](../SAFE) model (additional information [here](../SAFE#part-1)). This can be downloaded from GDrive as explained in ["Download the model data"](#download-the-model-data)
- The JSON file from the output of [Part 1](#part-1) (e.g., `digraph_instructions_embeddings_200.json` or `digraph_numerical_features.json`)
- The model checkpoint (only if the model is used in inference mode, i.e., during validation and testing).

The model will produce the following **output**:
- A set of CSV files with the similarity (column `sim`) for the functions selected for validation and testing
- A `config.json` file with the configuration used to run the test. This includes the parameters and the path of the CSV and JSON files in input. This file is useful for debugging and tracking different experiments
- A `s2v.log` file with the logs from the neural network. To improve logging, use the `--debug` (`-d`) option
- The model checkpoint (only if the model is trained).


### Instructions with Docker
The following are the concrete steps to run the analysis within the provided Docker container:
1. Build the docker image: 
```bash
docker build --no-cache NeuralNetwork/ -t gnn-s2v-neuralnetwork
```

2. Run the GNN-s2v neural network within the Docker container:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-s2v-neuralnetwork /code/s2v.py (--train | --validate | --test) [--num_epochs 5] \
        --network_type {annotations,arith_mean,attention_mean,rnn} \
        --features_type {none,numerical,asm} \
        --dataset {one,two,vuln} \
        -c /code/model_checkpoint_$(date +'%Y-%m-%d') \
        -o /output/Dataset-x
```

The `s2v.py` program uses the path to the `/input` folder to locate the necessary files to run the training, validation and testing for the Dataset-1, Dataset-2 and Dataset-Vulnerability. The program uses the default paths to locate the `embeddings.npy` and `digraph_instructions_embeddings_200.json` (or `digraph_numerical_features.json`) files under the `/instruction_embeddings` and `/preprocessing` folders. Different paths can be specified using different command line options.

Use the `--dataset` option to select the corresponding dataset: `--dataset one`, `--dataset two` or `--dataset vuln`.

Use the `--network_type` and `--features_type` options to select the combination of neural network and features to use. Available options include the models from the two papers "Investigating Graph Embedding Neural Networks with Unsupervised Features Extraction for Binary Analysis" and "Neural network-based graph embedding for cross-platform binary code similarity detection". The following is the list of accepted combinations:
```bash
# For the ML model in "Neural network-based graph embedding for cross-platform binary code similarity detection."
--network_type annotations      --features_type none
--network_type annotations      --features_type numerical 

# For the ML models in "Investigating Graph Embedding Neural Networks with Unsupervised Features Extraction for Binary Analysis."
--network_type arith_mean       --features_type asm --max_instructions 200
--network_type attention_mean   --features_type asm --max_instructions 200
--network_type rnn              --features_type asm --max_instructions 200
```
Please note that `--max-instructions` should be set to the same value as in [`digraph_instructions_embeddings.py`](Preprocessing/digraph_instructions_embeddings.py) (default is 200).

Use the `--random_embeddings` option to replace the pretrained embeddings with random ones.

Use the `--trainable_embeddings` option to train the embeddings with the rest of the neural network.

* You can see all options of the `s2v.py` command with:
```bash
docker run --rm -it gnn-s2v-neuralnetwork /code/s2v.py --help
```

---

* Example: run the training on the Dataset-1
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-s2v-neuralnetwork /code/s2v.py \
        --train \
        --network_type annotations \
        --features_type numerical \
        --num_epochs 5 \
        --dataset one \
        -c /output/model_checkpoint_$(date +'%Y-%m-%d') \
        -o /output/Dataset-1_training
```

The new trained model will be saved in `$(pwd)/NeuralNetwork/model_checkpoint_$(date +'%Y-%m-%d')`. Use the `--restore` option to continue the training from an existing checkpoint.

* Example: run the validation on Dataset-1 using the model_checkpoint that we trained on Dataset-1:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-s2v-neuralnetwork /code/s2v.py \
        --validate \
        --network_type annotations \
        --features_type numerical \
        --dataset one \
        -c /code/model_checkpoint_annotations_numerical_epoch5/ \
        -o /output/Dataset-1_validation
```


* Example: run the testing on Dataset-1 using the model_checkpoint that we trained on Dataset-1:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-s2v-neuralnetwork /code/s2v.py \
        --test \
        --network_type annotations \
        --features_type numerical \
        --dataset one \
        -c /code/model_checkpoint_annotations_numerical_epoch5/ \
        -o /output/Dataset-1_testing
```


* Example: run the testing on Dataset-2 using the model_checkpoint that we trained on Dataset-1:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-s2v-neuralnetwork /code/s2v.py \
        --test \
        --network_type annotations \
        --features_type numerical \
        --dataset two \
        -c /code/model_checkpoint_annotations_numerical_epoch5/ \
        -o /output/Dataset-2_testing
```


* Example: run the testing on Dataset-Vulnerability using the model_checkpoint that we trained on Dataset-1:
```bash
docker run --rm \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Pretraining/Dataset-1_training:/instruction_embeddings \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork/:/output \
    -it gnn-s2v-neuralnetwork /code/s2v.py \
        --test \
        --network_type annotations \
        --features_type numerical \
        --dataset vuln \
        -c /code/model_checkpoint_annotations_numerical_epoch5/ \
        -o /output/Dataset-Vulnerability_testing
```


## How to use GNN-s2v on a new dataset of functions

The following are the main steps that are needed to run GNN-s2v on a new dataset of functions.

### Training

1. Create a CSV file with the selected functions for training. Example [here](../../DBs/Dataset-1/training_Dataset-1.csv). `idb_path` and `fva` are the "primary keys" used to uniquely identify a function. The only requirement is to have the same function (i.e., the same function name) to be compiled under different settings (e.g., compilers, architectures, optimizations). The more the variants for each function, the better the model can generalize.
2. Extract the features using the ACFG disasm or ACFG features IDA plugins, depending on the model of interest, following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). The `idb_path` for the selected functions must be a valid path to an IDB file to run the IDA plugin correctly.
3. (Optional) Run the pretraining tool to pretrain the instruction embeddings following the instructions in the SAFE [README](../SAFE#part-1).
3. Run the GNN-s2v preprocessing tool following the instructions in [Part 1](#part-1).
4. Run the GNN-s2v neural network in training mode (`--train`) following the instructions in [Part 2](#part-2).

### Validation and testing

1. Create a CSV file with the pairs of functions selected for validation and testing. Example [here](../../DBs/Dataset-1/pairs). (`idb_path_1`, `fva_1`) and (`idb_path_2`, `fva_2`) are the "primary keys".
2. Extract the features using the ACFG disasm or ACFG features IDA plugins, depending on the model of interest, following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). `idb_path_1` and `idb_path_2` for the selected functions must be valid paths to the IDB
files to run the IDA plugin correctly.
3. Run the GNN-s2v preprocessing tool following the instructions in [Part 1](#part-1).
4. Run the GNN-s2v neural network in testing mode (`--test`) following the instructions in [Part 2](#part-2). 

## Additional notes

* The model checkpoints we provide were trained using the functions of [Dataset-1](../../DBs/Dataset-1/), which have been compiled for Linux using three architectures (x86-64, ARM 32/64 and MIPS 32/64), five optimizations, and two  compilers (GCC and CLANG). Do not use the model to infer the similarity for functions compiled in different settings (e.g., for Windows), but retrain it following the instructions above.


## Copyright information about the GNN-s2v models

The [neural network](NeuralNetwork) implementation includes part of the code from https://github.com/lucamassarelli/Unsupervised-Features-Learning-For-Binary-Similarity which is licensed under CC BY-NC-SA 4.0.