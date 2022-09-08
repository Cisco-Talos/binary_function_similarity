# The datasets

This directory includes the data used to evaluate the similarity approaches in all the different test cases.
Each dataset includes the selected functions, the corresponding features, and the scripts to generate them.

The data is organized in the following way:
- [Dataset-1](Dataset-1) contains the data used to train, validate and test the similarity approaches
- [Dataset-1-CodeCMR](Dataset-1-CodeCMR) is a subset of Dataset-1 designed specifically to test the CodeCMR/BinaryAI approach
- [Dataset-2](Dataset-2) is another "testing only" dataset
- [Dataset-Vulnerability](Dataset-Vulnerability) contains the data to evaluate the similarity approaches on the "vulnerability search" test case.

## Download the features for each dataset

**Warning: the following steps will require about 38GB of free disk space.**

To download the features from [Google Drive](https://drive.google.com/drive/folders/1uqZb0geb4CgDe9XEczZhNcyfBQM1TusG?usp=sharing) use the [`gdrive_download.py`](../gdrive_download.py) Python3 script and follow the instructions below:

1. Install the Python3 [virtualenv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/#installing-virtualenv)

2. Create a new virtualenv and install the required packages
```bash
# create a new "env" environment
python3 -m venv ../env
# enter the virtual environment
source ../env/bin/activate

# Install the requirements in the current environment
pip install -r ../requirements.txt
```

3. Download and unzip the features in the corresponding folders:
```bash
python3 ../gdrive_download.py --features
```

The features will be unzipped in the following directories:
```bash
DBs/Dataset-1/
DBs/Dataset-1-CodeCMR/
DBs/Dataset-2/
DBs/Dataset-Vulnerability/
```


## Dataset-1
*The instructions on how to recreate the dataset and extract the features are included below.*

The following is a list of the main files and subfolders:
```
Dataset-1
├── Dataset-1 creation.ipynb
├── Dataset-1 plots.ipynb
├── Dataset-1 sanity check.ipynb
├── features
│    ├── flowchart_Dataset-1.csv
│    ├── testing
│    │   ├── acfg_disasm_Dataset-1_testing
│    │   ├── acfg_features_Dataset-1_testing
│    │   ├── fss_Dataset-1_testing
│    │   ├── selected_testing_Dataset-1.json
│    │   └── zeek_Dataset-1_testing.json
│    ├── training
│    │   ├── acfg_disasm_Dataset-1_training
│    │   ├── acfg_features_Dataset-1_training
│    │   ├── fss_Dataset-1_training
│    │   ├── selected_training_Dataset-1.json
│    │   └── zeek_Dataset-1_training.json
│    └── validation
│        ├── acfg_disasm_Dataset-1_validation
│        ├── acfg_features_Dataset-1_validation
│        ├── fss_Dataset-1_validation
│        ├── selected_validation_Dataset-1.json
│        └── zeek_Dataset-1_validation.json
├── pairs
│    ├── testing
│    │   ├── neg_rank_testing_Dataset-1.csv
│    │   ├── neg_testing_Dataset-1.csv
│    │   ├── pos_rank_testing_Dataset-1.csv
│    │   └── pos_testing_Dataset-1.csv
│    └── validation
│        ├── neg_validation_Dataset-1.csv
│        └── pos_validation_Dataset-1.csv
├── testing_Dataset-1.csv
├── training_Dataset-1.csv
└── validation_Dataset-1.csv
```

**Ipython notebooks**:
* `Dataset-1 creation.ipynb`: recreate the dataset
* `Dataset-1 plots.ipynb`: display the dataset composition
* `Dataset-1 sanity check.ipynb`: verify that none of the data is missing

**All the functions**:
* `features/flowchart_Dataset-1.csv`: functions with at least five basic blocks
```csv
CSV columns:
idb_path,fva,func_name,start_ea,end_ea,bb_num,bb_list,hashopcodes
```

**Selected functions**:
* `validation_Dataset-1.csv`: selected functions for *training* in CSV format
* `training_Dataset-1.csv`: selected functions for *validation* in CSV format
* `testing_Dataset-1.csv`: selected functions for *testing* in CSV format
```csv
CSV columns:
idx,idb_path,fva,func_name,start_ea,end_ea,bb_num,hashopcodes,project,library,arch,bit,compiler,version,optimizations
```
* `features/training/selected_training_Dataset-1.json`: selected functions for *training* in JSON format
* `features/validation/selected_validation_Dataset-1.json`: selected functions for *validation* in JSON format
* `features/testing/selected_testing_Dataset-1.json`: selected functions for *testing* in JSON format

**Function pairs**:
* `pairs/validation/*.csv`: function pairs used for *validation* in CSV format
* `pairs/testing/*.csv`: function pairs used for *testing* in CSV format
```csv
CSV columns:
idx,idb_path_1,fva_1,func_name_1,idb_path_2,fva_2,func_name_2,db_type
```

**Features files**:
* `features/*/fss_Dataset-1_*`: the JSON files extracted using the FunctionSimSearch IDA plugin
* `features/*/acfg_features_Dataset-1_*`: the JSON files extracted using the "acfg features" IDA plugin
* `features/*/acfg_disasm_Dataset-1_*`: the JSON files extracted using the "acfg disasm" IDA plugin
* `features/*/zeek_Dataset-1_*`: the JSON file from Zeek features extraction script

#### [Optional] Dataset creation and features extraction steps
This step is *optional* because the dataset and the features are already included in the release.

Use the following steps only if you want to *recreate* the Dataset-1:
1. Download the Binaries of Dataset-1 following [these instructions](../Binaries/README.md#download-the-compiled-binaries-for-each-dataset). Then, generate the [corresponding IDBs](../IDA_scripts#generate-the-idbs-ida-databases)
2. Run the [IDA_flowchart](../IDA_scripts/IDA_flowchart) plugin to get the list of candidate functions
3. Use the [Dataset-1 creation.ipynb](Dataset-1/Dataset-1%20creation.ipynb) IPython Notebook to generate the function pairs and the list of selected functions
    * **TODO**: This IPython notebook will be released soon.
4. Run the [IDA_acfg_disasm](../IDA_scripts/IDA_acfg_disasm) and [IDA_acfg_features](../IDA_scripts/IDA_acfg_features) plugins to extract the features used by the ML models
5. Run the [Catalog1](../Models/Catalog1) and the [IDA_fss](../Models/functionsimsearch/IDA_fss) plugins to extract the features for Catalog1 and FunctionSimSearch.


## Dataset-1-CodeCMR
*The instructions on how to recreate the dataset and extract the features are included below.*

The following is a list of the main files and subfolders:
```
Dataset-1-CodeCMR
├── Dataset-1-CodeCMR creation.ipynb
├── Dataset-1-CodeCMR example.ipynb
├── Dataset-1-CodeCMR plots.ipynb
├── Dataset-1-CodeCMR sanity check.ipynb
├── features
│    ├── testing
│    │   ├── selected_testing_Dataset-1-CodeCMR.json
│    │   ├── ...
│    ├── training
│    │   ├── selected_training_Dataset-1-CodeCMR.json
│    │   ├── ...
│    └── validation
│    │   ├── selected_validation_Dataset-1-CodeCMR.json
│    │   ├── ...
├── pairs
│    ├── testing
│    │   ├── neg_rank_testing_Dataset-1-CodeCMR.csv
│    │   ├── neg_testing_Dataset-1-CodeCMR.csv
│    │   ├── pos_rank_testing_Dataset-1-CodeCMR.csv
│    │   └── pos_testing_Dataset-1-CodeCMR.csv
│    └── validation
│        ├── neg_validation_Dataset-1-CodeCMR.csv
│        └── pos_validation_Dataset-1-CodeCMR.csv
├── testing_Dataset-1-CodeCMR.csv
├── training_Dataset-1-CodeCMR.csv
└── validation_Dataset-1-CodeCMR.csv
```

**Ipython notebooks**:
* `Dataset-1-CodeCMR creation.ipynb`: recreate the dataset
* `Dataset-1-CodeCMR sanity check.ipynb`: verify that the required data is available
* `Dataset-1-CodeCMR plots.ipynb`: display the dataset composition
* `Dataset-1-CodeCMR example.ipynb`: example of how to use data in the pickle files

**Selected functions**:
* `training_Dataset-1-CodeCMR.csv`: selected functions for *training* in CSV format
* `validation_Dataset-1-CodeCMR.csv`: selected functions for *validation* in CSV format
* `testing_Dataset-1-CodeCMR.csv`: selected functions for *testing* in CSV format
```csv
CSV columns:
idx,idb_path,fva,func_name,start_ea,end_ea,bb_num,hashopcodes,project,library,arch,bit,compiler,version,optimizations,pickle_path
```
* `features/training/selected_training_Dataset-1-CodeCMR.json`: selected functions for *training* in JSON format
* `features/validation/selected_validation_Dataset-1-CodeCMR.json`: selected functions for *validation* in JSON format
* `features/testing/selected_testing_Dataset-1-CodeCMR.json`: selected functions for *testing* in JSON format

**Features files**:
* `features/training/*.pkl`: selected features for the *training* functions
* `features/validation/*.pkl`: selected features for the *validation* functions
* `features/testing/*.pkl`: selected features for the *testing* functions

**Function pairs**:
* `pairs/validation/*.csv`: function pairs used for *validation* in CSV format
* `pairs/testing/*.csv`: function pairs used for *testing* in CSV format
```csv
CSV columns:
idx,idb_path_1,pickle_path_1,fva_1,func_name_1,idb_path_2,pickle_path_2,fva_2,func_name_2,db_type
```


#### [Optional] Dataset creation and features extraction steps
This step is *optional* because the dataset and the features are already included in the release.

Use the following steps only if you want to *recreate* the Dataset-1-CodeCMR:
*Note: steps 1 and 2 are in common with Dataset-1*
1. Download the Binaries of Dataset-1 following [these instructions](../Binaries/README.md#download-the-compiled-binaries-for-each-dataset). Then, generate the [corresponding IDBs](../IDA_scripts#generate-the-idbs-ida-databases)
2. Run the [IDA_flowchart](../IDA_scripts/IDA_flowchart) plugin to get the list of candidate functions
3. Use the [Dataset-1-CodeCMR creation.ipynb](Dataset-1-CodeCMR/Dataset-1-CodeCMR%20creation.ipynb) IPython Notebook to generate the function pairs and the list of selected functions
    * **TODO**: This IPython notebook will be released soon.
4. Run the [IDA_CodeCMR](../Models/CodeCMR/IDA_CodeCMR) plugin to extract the pickle files with the selected features.


## Dataset-2
*The instructions on how to recreate the dataset and extract the features are included below.*

The following is a list of the main files and subfolders:
```
Dataset-2
├── Dataset-2 creation.ipynb
├── Dataset-2 plots.ipynb
├── Dataset-2 sanity check.ipynb
├── features
│    ├── acfg_disasm_Dataset-2
│    │   ├── ...
│    ├── acfg_features_Dataset-2
│    │   ├── ...
│    ├── catalog1_Dataset-2
│    │   ├── ...
│    ├── flowchart_Dataset-2.csv
│    ├── fss_Dataset-2
│    │   ├── ...
│    ├── selected_testing_Dataset-2.json
│    └── zeek_Dataset-2.json
├── pairs
│    ├── neg_rank_testing_Dataset-2.csv
│    ├── neg_testing_Dataset-2.csv
│    ├── pos_rank_testing_Dataset-2.csv
│    └── pos_testing_Dataset-2.csv
└── testing_Dataset-2.csv
```

**Ipython notebooks**:
* `Dataset-2 creation.ipynb`: recreate the dataset
* `Dataset-2 plots.ipynb`: display the dataset composition
* `Dataset-2 sanity check.ipynb`: verify that the required data is available

**All the functions**:
* `features/flowchart_Dataset-2.csv`: all the functions with at least five basic blocks
```csv
CSV columns:
idb_path,fva,func_name,start_ea,end_ea,bb_num,bb_list,hashopcodes
```

**Selected functions**:
* `testing_Dataset-2.csv`: selected functions for *testing* in CSV format
```csv
CSV columns:
idx,idb_path,fva,func_name,start_ea,end_ea,bb_num,hashopcodes,project,library,arch,bit,compiler,version,optimizations
```
* `features/selected_testing_Dataset-2.json`: selected functions for *testing* in JSON format

**Function pairs**:
* `pairs/*.csv`: the function pairs used for *testing* in CSV format
```csv
CSV columns:
idx,idb_path_1,fva_1,func_name_1,idb_path_2,fva_2,func_name_2,db_type
```

**Features files**:
* `features/fss_Dataset-2`: the JSON files extracted using the FunctionSimSearch IDA plugin
* `features/catalog1_Dataset-2`: the CSV files extracted using the Catalog1 IDA plugin
* `features/acfg_features_Dataset-2`: the JSON files extracted using the "acfg features" IDA plugin
* `features/acfg_disasm_Dataset-2`: the JSON files extracted using the "acfg disasm" IDA plugin
* `features/zeek_Dataset-2.json`: the JSON file from Zeek features extraction script.

#### [Optional] Dataset creation and features extraction steps
This step is *optional* because the dataset and the features are already included in the release.

Use the following steps only if you want to *recreate* the Dataset-2:
1. Download the Binaries of Dataset-2 following [these instructions](../Binaries/README.md#download-the-compiled-binaries-for-each-dataset). Then, generate the [corresponding IDBs](../IDA_scripts#generate-the-idbs-ida-databases)
2. Run the [IDA_flowchart](../IDA_scripts/IDA_flowchart) plugin to get the list of candidate functions
3. Use the [Dataset-2 creation.ipynb](Dataset-2/Dataset-2%20creation.ipynb) IPython Notebook to generate the function pairs and the list of selected functions
    * **TODO**: This IPython notebook will be released soon.
4. Run the [IDA_acfg_disasm](../IDA_scripts/IDA_acfg_disasm) and [IDA_acfg_features](../IDA_scripts/IDA_acfg_features) plugins to extract the features used by the ML models
5. Run the [Catalog1](../Models/Catalog1) and the [IDA_fss](../Models/functionsimsearch/IDA_fss) plugins to extract the features for Catalog1 and FunctionSimSearch.


## Dataset-Vulnerability
*The instructions on how to recreate the dataset and extract the features are included below.*

The following is a list of the main files and subfolders:
```
Dataset-Vulnerability
├── Dataset-Vulnerability creation.ipynb
├── Dataset-Vulnerability sanity check.ipynb
├── features
│        ├── acfg_disasm_Dataset-Vulnerability
│        ├── acfg_features_Dataset-Vulnerability
│        ├── catalog1_Dataset-Vulnerability
│        ├── flowchart_Dataset-Vulnerability.csv
│        ├── fss_Dataset-Vulnerability
│        ├── selected_Dataset-Vulnerability.json
│        └── zeek_Dataset-Vulnerability.json
├── pairs
│        └── pairs_testing_Dataset-Vulnerability.csv
└── testing_Dataset-Vulnerability.csv
```

**Ipython notebooks**:
* `Dataset-Vulnerability creation.ipynb`: recreate the dataset
* `Dataset-Vulnerability sanity check.ipynb`: verify that the required data is available

**All the functions**:
* `features/flowchart_Dataset-Vulnerability.csv`: all the functions with at least five basic blocks
```csv
CSV columns:
idb_path,fva,func_name,start_ea,end_ea,bb_num,bb_list,hashopcodes
```

**Selected functions**:
* `testing_Dataset-Vulnerability.csv`: selected functions in CSV format
```csv
CSV columns:
idx,idb_path,fva,func_name,start_ea,end_ea,bb_num,hashopcodes
```
* `features/selected_Dataset-Vulnerability.json`: selected functions in JSON format

**Function pairs**:
* `pairs/pairs_testing_Dataset-Vulnerability.csv`: the function pairs used for *testing* in CSV format
```csv
CSV columns:
idx,idb_path_1,fva_1,func_name_1,idb_path_2,fva_2,func_name_2,db_type
```

**Features files**:
* `features/fss_Dataset-Vulnerability`: the JSON files extracted using the FunctionSimSearch IDA plugin
* `features/catalog1_Dataset-Vulnerability`: the CSV files extracted using the Catalog1 IDA plugin
* `features/acfg_features_Dataset-Vulnerability`: the JSON files extracted using the "acfg features" IDA plugin
* `features/acfg_disasm_Dataset-Vulnerability`: the JSON files extracted using the "acfg disasm" IDA plugin
* `features/zeek_Dataset-Vulnerability.json`: the JSON file from Zeek features extraction script.

#### [Optional] Dataset creation and features extraction steps
This step is *optional* because the dataset and the features are already included in the release.

Use the following steps only if you want to *recreate* the Dataset-Vulnerability:
1. Download the Binaries of Dataset-Vulnerability following [these instructions](../Binaries/README.md#download-the-compiled-binaries-for-each-dataset). Then, generate the [corresponding IDBs](../IDA_scripts#generate-the-idbs-ida-databases)
2. Run the [IDA_flowchart](../IDA_scripts/IDA_flowchart) plugin to get the list of candidate functions
3. Use the [Dataset-Vulnerability creation.ipynb](Dataset-Vulnerability/Dataset-Vulnerability%20creation.ipynb) IPython Notebook to generate the function pairs and the list of selected functions
4. Run the [IDA_acfg_disasm](../IDA_scripts/IDA_acfg_disasm) and [IDA_acfg_features](../IDA_scripts/IDA_acfg_features) plugins to extract the features used by the ML models
5. Run the [Catalog1](../Models/Catalog1) and the [IDA_fss](../Models/functionsimsearch/IDA_fss) plugins to extract the features for Catalog1 and FunctionSimSearch.
