# Catalog1

The Catalog1 experiment requires running an IDA Pro plugin to extract the MinHash signature of a binary function.

## Requirements
1. Compile the Catalog1 library:
```
(cd catalog1/; make)
```

After compilation, `libcatalog1.so` will appear under `catalog1/bin`.

2. For the IDA Pro plugin, follow the list of requirements from the IDA_scripts [README](../../../IDA_scripts/README.md#requirements)

## The IDA Pro plugin
- **input**: the JSON file with the selected functions (`-j`) and the name of the CSV file in output (`-o`).
- **output**: one CSV file per Catalog1 signature size (default: `[16, 32, 64, 128]`)

**Note**: the path of the IDB files in the JSON in input **must be relative** to the `binary_function_similarity` directory. The Python3 script converts the relative path into a full path to correctly load the IDB in IDA Pro.

Example: run the plugins over the functions selected for the Dataset-Vulnerability test (requires the IDBs in the `IDBs/Dataset-Vulnerability` directory)
```bash
python3 cli_catalog1.py -j ../../DBs/Dataset-Vulnerability/features/selected_Dataset-Vulnerability.json -o Dataset-Vulnerability_catalog1.csv
```

Run unit tests:
```bash
python3 -m unittest test_catalog1.py

# optional - test on multiple files
python3 -m unittest test_large_catalog1.py
```

### Expected output
The plugin produces a set of CSV files with the following columns:
* `path`: idb path
* `address`: function address
* `size`: function size
* `catalog_hash_list`: catalog hashes, separated by `;`
* `time`: time to calculate the Catalog1 hashes on the function.

To compute the similarity between two Catalog1 signatures, use the Jaccard similarity as in the following example:
```python
def jaccard_similarity(s1, s2):
    return len(set(s1) & set(s2)) / len(set(s1) | set(s2))

a = [10534612, 42437122, 187632428, 38160894, 167893582, 20517613, 328764745, 40669729]
b = [15508139, 42437122, 83784247, 138119612, 167793573, 29886129, 35551260, 1210122]
print(jaccard_similarity(a, b)) # 0.06666666666666667
print(jaccard_similarity(a, a)) # 1.0
```

**Note:** if the function has less than 4 bytes, `min_function_size_error` is inserted in the `catalog_hash_list` column.

## More info about the Catalog1 library
Catalog1 implements the MinHash algorithm and the library can be used to compute a signature over any stream of binary data:
```python
from catalog1.catalog_fast import sign
from catalog1.catalog_slow import slow_sign

SIG_SIZE = 128 # Example values: 16, 32, 64, 128

binary_data = "..."

# C implementation (fast)
signature = sign(binary_data, SIG_SIZE)

# Python3 implementation
signature_slow = slow_sign(binary_data, SIG_SIZE)
````

## Copyright information about Catalog1
The code of [Catalog1](catalog1) is taken from the xorpd repository of the [fcatalog_server](https://github.com/xorpd/fcatalog_server), which is released under the GNU General Public License v3.0.

* [Link](https://www.xorpd.net/pages/fcatalog.html) to the blogpost.    
* [Link](https://github.com/xorpd/fcatalog_server/tree/master/catalog1) to the Catalog1 C implementation.
* [Link](https://github.com/xorpd/fcatalog_server/blob/master/fcatalog/fcatalog/catalog1.py) to the Catalog1 Python3 implementation.

Changelog wrt the [original version](https://github.com/xorpd/fcatalog_server/tree/master/catalog1):

* The `catalog1/Makefile` has been modified.
