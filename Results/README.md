# Results

This folder contains the results of the experiments and the IPython notebooks to extract the different metrics and generate the plots.

## Download the output data for each model we tested

**Warning: the following steps will require about 13GB of free disk space.**

To download the data from [Google Drive](https://drive.google.com/drive/folders/13kyJagd1eBR3CC5shnR5DdCGOFWF0Dbe?usp=sharing) use the [`gdrive_download.py`](../gdrive_download.py) Python3 script and follow the instructions below:

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

3. Download and unzip the data in the corresponding folders:
```bash
python3 ../gdrive_download.py --results
```

The data will be unzipped in the following directories:
```bash
Results/data/Dataset-1
Results/data/Dataset-1-CodeCMR
Results/data/Dataset-2
Results/data/Dataset-Vulnerability
Results/data/raw_results
```

## Process the data to extract the different metrics and generate the plots

Most of the model implementations directly return the similarity between the function pairs for each [dataset](../DBs/) we tested. The CSV files with the results are saved in the corresponding `Dataset` folder under the `data` directory.

All the CSV files use the same header:
```csv
idb_path_1,fva_1,idb_path_2,fva_2,sim
```
* `idb_path` and `fva` are used as "primary keys" to identify a single function
* The `sim` column contains the similarity (distance) value computed using the specific metric required by each approach.

However, some models require an intermediate step to convert the output to this standard form. The `data/raw_results` folder includes the output from Asm2vec/Doc2vec, Catalog1, CodeCMR and FunctionSimSearch.
* Use the [`Convert Asm2vec results`](notebooks/Convert%20Asm2vec%20results.ipynb) IPython notebook to process the Asm2vec and Doc2vec output (`data/raw_results/Asm2vec`)
* Use the [`Convert Catalog1 results`](notebooks/Convert%20Catalog1%20results.ipynb) IPython notebook to process the Catalog1 output (`data/raw_results/Catalog1`)
* Use the [`Convert CodeCMR results`](./notebooks/Convert%20CodeCMR%20results.ipynb) IPython notebook to process the CodeCMR output (`data/raw_results/CodeCMR`)
* Use the [`Convert FunctionSimSearch results`](./notebooks/Convert%20FunctionSimSearch%20results.ipynb) IPython notebook to process the FunctionSimSearch output (`data/raw_results/FunctionSimSearch`).

Finally, there are three IPython notebooks to extract the metrics for all the experiments:
- [`AUC and similarity plots`](./notebooks/AUC%20and%20similarity%20plots.ipynb) computes the AUC for each task and model configuration
- [`MRR@10 and Recall@K`](./notebooks/MRR@10%20and%20Recall@K.ipynb) computes the *MRR@10* and *Recall@K* metrics
- [`Vulnerability task eval`](./notebooks/Vulnerability%20task%20eval.ipynb) generates the metrics for the Vulnerability test case.

The output is saved in the [`metrics_and_plots`](./notebooks/metrics_and_plots) folder.