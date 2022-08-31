# Asm2vec and Doc2vec

Our implementation of Asm2vec and Doc2vec is constituted by two components. The first one takes as input the [ACFG disasm](../../IDA_scripts/#ida-acfg-disasm) data and it produces as output the random walks over the selected functions. Those are then taken as input by the second part, which implements the machine learning component.

## Part 1
The first part of the Asm2vec tool is implemented in a Python3 script called [`i2v_preprocessing.py`](i2v_preprocessing.py). We also provide a [Docker](Dockerfile) container with the required dependencies.

The **input** of the script is a folder with the JSON files extracted via the ACFG disasm IDA plugin:
- For the [Datasets](../../DBs) we have released, the JSON files are already available in the `features` directory. Please, note that features are downloaded from GDrive as explained in the [README](../../DBs/#download-the-features-for-each-dataset).
- To extract the features for a new set of binaries, run the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm).

There are a number of configurable parameters, such as:
- `-a2v` or `-d2v`, if the output must be compatible with the Asm2vec or the Doc2vec (PV-DM or PV-DBOW) model
- `--num_rwalks`, `--max_walk_len` and `--max_walk_tokens` are used to configure the number and length of each random walk
- `--min_frequency` is the minimum number of occurrences for a token to be selected
- `--workers` defines the number of parallel processes: the higher the better, but depends on the number of CPU cores.

The script will produce a folder with the following **output**:
- A file called `random_walks_{model}.csv` that contains the random walks over the selected functions
- A file called `vocabulary.csv` with the list of tokens selected to train the neural network
- A file called `counter_dict.json` which maps each token to its frequency counter
- A file called `vocabulary_dropped.csv` with the list of infrequent tokens that are discarded during the analysis
- A file called `id2func.json` which maps each selected function to a numerical ID
- A file called `i2v_preprocessing.log` that contains the logs of the analysis and may be useful for debugging.

### Instructions with Docker
These are the concrete steps to run the analysis within the provided Docker container:

1. Build the docker image: 
```bash
docker build -t asm2vec .
```

2. Run the [i2v_preprocessing.py](i2v_preprocessing.py) script within the docker container:
```bash
docker run --rm -v <path_to_the_acfg_disasm_dir>:/input -v <path_to_the_output_dir>:/output -it asm2vec /code/i2v_preprocessing.py -d [--workers 4] [-a2v, -d2v] -i /input -o /output/
```

You can see all the command line options using:
```bash
docker run --rm -it asm2vec /code/i2v_preprocessing.py --help
```

Example (1): run the [i2v_preprocessing.py](i2v_preprocessing.py) script for the training part of Dataset-1 with `-a2v`:
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-1/features/training/acfg_disasm_Dataset-1_training:/input -v $(pwd):/output -it asm2vec /code/i2v_preprocessing.py -d -w4 -a2v -i /input -o /output/a2v_preprocessing_Dataset-1-training
```

Example (2): run the [i2v_preprocessing.py](i2v_preprocessing.py) script for the training part of Dataset-1 with `-d2v`:
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-1/features/training/acfg_disasm_Dataset-1_training:/input -v $(pwd):/output -it asm2vec /code/i2v_preprocessing.py -d -w4 -d2v -i /input -o /output/d2v_preprocessing_Dataset-1-training
```

When processing validation or testing data, use the `-v` (`--vocabulary`) option to give in input the training vocabulary.

Example (3): run the [i2v_preprocessing.py](i2v_preprocessing.py) script for the testing part of Dataset-1 with `-a2v`:
```bash
docker run --rm -v $(pwd)/../../DBs/Dataset-1/features/testing/acfg_disasm_Dataset-1_testing:/input -v $(pwd)/a2v_preprocessing_Dataset-1-training:/training_data -v $(pwd):/output -it asm2vec /code/i2v_preprocessing.py -d -w4 -a2v -i /input -v /training_data/vocabulary.csv -o /output/a2v_preprocessing_Dataset-1-testing
```

## Part 2
The machine learning component of Asm2vec is implemented on top of [Gensim 3.8](https://github.com/RaRe-Technologies/gensim). For the details of the implementation, please refer to the [patch](asm2vec.patch) that we created. The [`i2v.py`](i2v.py) script is used to run the training and inference for the Asm2vec and Doc2vec (PV-DM or PV-DBOW) models. The [Docker](Dockerfile) container of Part 1 includes the required dependencies for the neural network part too.

The [`i2v.py`](i2v.py) script takes in **input**:
- The output of [i2v_preprocessing.py](i2v_preprocessing.py), including the selected vocabulary, the random walks and the tokens frequency.
- The `{model}_checkpoint` (only if the model is used in inference mode, i.e., during validation and testing).

There are a number of configurable parameters, such as:
- Use the `--pvdm`, `--pvdbow` or `--asm2vec` option to select the model to use (it must be the same for training and inference)
- Select `--train`, or `--inference` mode
- Configure the number of epochs via the `--epochs` parameter
- Use the `--workers` option to select the number of parallel workers to use.

The code of [`i2v.py`](i2v.py) contains others hardcoded parameters that are marked as `# FIXED PARAM`. Experimenting with different values for those parameters has to be studied.

The model will produce a folder with the following **output** when launched in *training mode*:
- A file called `{model}_checkpoint` which contains a backup of the model after training. This can be reused for the inference
- A file called `i2v.log` which contains the logs of the analysis and may be useful for debugging.

The model will produce a folder with the following **output** when launched in *inference mode*:
- A CSV called `embeddings.csv` which contains the embedding produced by the model for each function in the dataset
- A file called `i2v.log` which contains the logs of the analysis and may be useful for debugging.

Note: at inference time, the Asm2vec and Doc2vec models require *updating* the internal weights for a number of epochs (similarly to what happens during the *training*). However, only the matrix corresponding to the functions is updated, while the matrix of the tokens is fixed. This behavior is different from the other *traditional* machine learning models.

The similarity between two functions is computed using the cosine similarity between the corresponding embeddings.

### Instructions with Docker
1. Run the neural network model
```bash
docker run --rm -v <path_to_i2v_preprocessing_output_folder>:/input -v $(pwd):/output -it asm2vec /code/i2v.py -d [--asm2vec, --pvdm, --pvdbow] [--train, --inference, --log] -e1 -w4 --inputdir /input/ -o /output/output_folder
```

You can see all the command line options using:
```bash
docker run --rm -it asm2vec /code/i2v.py --help
```

Example (1): train the Asm2vec model on Dataset-1.
```bash
docker run --rm -v $(pwd)/a2v_preprocessing_Dataset-1-training:/input -v $(pwd):/output -it asm2vec /code/i2v.py -d --asm2vec --train -e1 -w4 --inputdir /input/ -o /output/asm2vec_train_Dataset-1-training
```

Example (2): run the Asm2vec model in inference mode on the testing data of Dataset-1.
```bash
docker run --rm -v $(pwd)/a2v_preprocessing_Dataset-1-testing:/input -v $(pwd)/asm2vec_train_Dataset-1-training:/checkpoint -v $(pwd):/output -it asm2vec /code/i2v.py -d --asm2vec --inference -e1 -w4 --inputdir /input/ -c /checkpoint -o /output/asm2vec_inference_Dataset-1-testing
```

## How to use Asm2vec and Doc2vec models on a new dataset of functions

The following are the main steps that are needed to run the Asm2vec and Doc2vec models on a new dataset of functions.

### Training

1. Create a CSV file with the selected functions for training. Example [here](../../DBs/Dataset-1/training_Dataset-1.csv). `idb_path` and `fva` are the "primary keys" used to uniquely identify a function. The only requirement is to have the same function (i.e., the same function name) to be compiled under different settings (e.g., compilers, architectures, optimizations). The more the variants for each function, the better the model can generalize.
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). The `idb_path` for the selected functions must be a valid path to an IDB file to run the IDA plugin correctly.
3. Run the [i2v_preprocessing.py](i2v_preprocessing.py) script following the instructions in [Part 1](#part-1).
4. Run the [i2v.py](i2v.py) script in training mode (`--train`) following the instructions in [Part 2](#part-2).

### Validation and testing

1. Create a CSV file with the pairs of functions selected for validation and testing. Example [here](../../DBs/Dataset-1/pairs). (`idb_path_1`, `fva_1`) and (`idb_path_2`, `fva_2`) are the "primary keys".
2. Extract the features using the ACFG disasm IDA plugin following the instructions in the [README](../../IDA_scripts/#ida-acfg-disasm). `idb_path_1` and `idb_path_2` for the selected functions must be valid paths to the IDBs file to run the IDA plugin correctly.
3. Run the [i2v_preprocessing.py](i2v_preprocessing.py) script following the instructions in [Part 1](#part-1).
4. Run the [i2v.py](i2v.py) script in inference mode (`--inference`) following the instructions in [Part 2](#part-2).
5. Compute the function similarity using the *cosine similarity* between the corresponding embeddings.

## Additional notes

* The Asm2vec and Doc2vec (PV-DM or PV-DBOW) models can only compare functions compiled for the same architecture, in other words it cannot be used for the XC (cross-compiler) test case. However, the models can be trained with functions from different architectures at the same time.

## Copyright information about Gensim
[Gensim](https://github.com/RaRe-Technologies/gensim) is released under LGPL-2.1 license.


