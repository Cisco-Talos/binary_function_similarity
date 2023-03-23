# Binary Function Similarity
This repository contains the code, the dataset and additional technical information for our USENIX Security '22 paper:
> Andrea Marcelli, Mariano Graziano, Xabier Ugarte-Pedrero, Yanick Fratantonio, Mohamad Mansouri, Davide Balzarotti. *How Machine Learning Is Solving the Binary Function Similarity Problem*. USENIX Security '22.

The paper is available at this [link](https://www.usenix.org/system/files/sec22-marcelli.pdf).


## Additional technical information
The technical report, with additional information on the dataset and the selected approaches, is available at this [link](Additional%20technical%20information.pdf).


## Artifacts
The repository is structured in the following way:

* [Binaries](Binaries/): the compiled binaries and the scripts to compile them. Binaries are downloaded from GDrive via a Python script
* [IDBs](IDBs/): where the IDA Pro databases (IDBs) are stored after analysis. IDBs are generated via a Python script and IDA Pro
* [DBs](DBs/): the datasets of selected functions, the corresponding features, and the scripts to generate them
* [IDA_scripts](IDA_scripts/): the IDA Pro scripts used for the features extraction
* [Models](Models/): the code for the approaches we tested
* [Results](Results/): the results of our experiments on all the test cases and the code to extract the different metrics.


## What to do next?
The following is a list of the main steps to follow based on the most common use cases:

* **Reproduce the experiments presented in the paper**
	- *Note*: the binaries ([Binaries](Binaries/)) and the corresponding IDA Pro Databases ([IDBs](IDBs/)) *are only needed* to create a new dataset or to extract additional features. In order to reproduce the experiments or run new tests with the current set of features, [DBs](DBs/) and [Models](Models/) already contain the required data.

	1. The [DBs](DBs/) folder contains the input data needed to reproduce the results for each tested approach, including extracted features
	2. Refer to the README of each approach in the [Models](Models/) folder for detailed instructions on how to run it
	3. Follow the README and use the scripts in the [Results](Results/) folder to collect the different metrics.

* **Test a new approach on our datasets**
	1. Check the README in the [DBs](DBs/) folder to decide which data to use based on each test case
	2. Reuse the existing [IDA Pro scripts](IDA_scripts/) codebase for the features extractions and pre/post-processing code to minimize evaluation differences
	3. Follow the README and use the scripts in the [Results](Results/) folder to collect the different metrics.
	
* **Use one of the existing approaches to infer new functions**
	- *Note*: the current workflow and code has been written to optimize the evaluation of the similarity engines on a "fixed" dataset of functions and their features.
	This makes the inference on a new dataset slightly complex, as it requires to follow different steps for each approach. A simplification may be addressed in a future release.

	1. Refer to the README of each approach in [Models](Models/) for detailed instructions on how to run it in *inference mode*
	2. Use the corresponding [IDA Pro script](IDA_scripts/) to extract the features that are needed by that specific approach
	3. Some approaches require to run a specific post-processing script to convert the extracted features into the requested format
	4. *Be aware* of the limitations of the ML models: new architectures, compilers and compiler options may require retraining them.

## How to cite our work
Please use the following BibTeX:
```
@inproceedings {280046,
author = {Andrea Marcelli and Mariano Graziano and Xabier Ugarte-Pedrero and Yanick Fratantonio and Mohamad Mansouri and Davide Balzarotti},
title = {How Machine Learning Is Solving the Binary Function Similarity Problem},
booktitle = {31st USENIX Security Symposium (USENIX Security 22)},
year = {2022},
isbn = {978-1-939133-31-1},
address = {Boston, MA},
pages = {2099--2116},
url = {https://www.usenix.org/conference/usenixsecurity22/presentation/marcelli},
publisher = {USENIX Association},
month = aug,
}
```

## Errata corrects
Our corrections to the published paper:

- From Section *3.2 Selected Approaches*: "First, the binary diffing tools grouped in the middle box [13,16,83] have all been designed for a direct comparison of two binaries (e.g., they use the call graph) and they are all mono-architecture." This sentence is inaccurate because Bindiff and Diaphora also support the cross-architecture comparisons.

## License
The code in this repository is licensed under the [MIT License](LICENSE), however some models and scripts depend on or pull in code that have different licenses.
- For the compiled binaries, these licenses can be found in full in the [`Binaries/LICENSES` directory](Binaries/LICENSES).
- The [`Asm2vec` and `Doc2vec` models](Models/Asm2vec/) are implemented on top of the [Gensim project](https://github.com/RaRe-Technologies/gensim) which is released under LGPL-2.1.
- The [`IDA_codeCMR.py`](Models/CodeCMR/IDA_CodeCMR/IDA_codeCMR.py) plugin is released under GPL v3.
- The [`catalog1` folder](Models/Catalog1/catalog1) contains the source code of the Catalog1 library which is licensed under GPL v3.
- The [`FunctionSimSearch` model](Models/functionsimsearch/) pulls the code from the [FunctionSimSearch project](https://github.com/googleprojectzero/functionsimsearch) which is released under Apache License 2.0.
- The [`SAFE` model](Models/SAFE) contains part of the original source code of SAFE which is licensed under GPL v3.
- The [`GGSNN` and `GMN` models](Models/GGSNN-GMN) contain part of the original [source code](https://github.com/deepmind/deepmind-research/blob/master/graph_matching_networks/graph_matching_networks.ipynb) which is licensed under Apache License 2.0.
- The [`GNN-s2v` models](Models/GNN-s2v) contains part of the original [source code](https://github.com/lucamassarelli/Unsupervised-Features-Learning-For-Binary-Similarity) which is licensed under CC BY-NC-SA 4.0.

## Bugs and feedback
For help or issues, please submit a GitHub issue.
