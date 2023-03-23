##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  MIT License                                                               #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  Permission is hereby granted, free of charge, to any person obtaining     #
#  a copy of this software and associated documentation files (the           #
#  "Software"), to deal in the Software without restriction, including       #
#  without limitation the rights to use, copy, modify, merge, publish,       #
#  distribute, sublicense, and/or sell copies of the Software, and to        #
#  permit persons to whom the Software is furnished to do so, subject to     #
#  the following conditions:                                                 #
#                                                                            #
#  The above copyright notice and this permission notice shall be            #
#  included in all copies or substantial portions of the Software.           #
#                                                                            #
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,           #
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF        #
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                     #
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE    #
#  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION    #
#  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION     #
#  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.           #
#                                                                            #
#  Implementation of the models based on Graph Neural Network (GNN)          #
#    and Structure2vec (s2v).                                                #
#                                                                            #
##############################################################################

from .pair_factory_base import PairData
from .pair_factory_inference import PairFactoryInference
from .pair_factory_testing import PairFactoryTesting
from .pair_factory_training import PairFactoryTraining

import logging

log = logging.getLogger("s2v")


def build_train_validation_generators(config):
    """Utility function to build train and validation batch generators.

    Args
      config: global configuration
    """
    training_gen = PairFactoryTraining(
        func_path=config["training"]["df_train_path"],
        feat_path=config["training"]["features_train_path"][config["features_type"]],
        batch_size=config["batch_size"],
        features_type=config["features_type"],
        network_type=config["network_type"],
        max_num_vertices=config["max_num_vertices"],
        length_raw_features=config["length_raw_features"],
    )

    validation_gen = PairFactoryTesting(
        pos_path=config["validation"]["positive_path"],
        neg_path=config["validation"]["negative_path"],
        feat_path=config["validation"]["features_validation_path"][
            config["features_type"]
        ],
        batch_size=config["batch_size"],
        features_type=config["features_type"],
        network_type=config["network_type"],
        max_num_vertices=config["max_num_vertices"],
        length_raw_features=config["length_raw_features"],
    )

    return training_gen, validation_gen


def build_testing_generator(config, csv_path):
    """Build a batch_generator from the CSV in input.

    Args
      config: global configuration
      csv_path: CSV input path
    """
    testing_gen = PairFactoryInference(
        func_path=csv_path,
        feat_path=config["testing"]["features_testing_path"][config["features_type"]],
        batch_size=config["batch_size"],
        features_type=config["features_type"],
        network_type=config["network_type"],
        max_num_vertices=config["max_num_vertices"],
        length_raw_features=config["length_raw_features"],
    )
    return testing_gen


def fill_feed_dict(placeholders, batch, network_type):
    """Create a feed dict for the given batch of data.

    Args
      placeholders: a dict of placeholders as defined in s2v_network*.py
      batch: a batch of data, should be either a single `PairData`
        instance for triplet training or single batch evaluation,
        or a tuple of (func_data, labels) for pairwise training.
      network_type: type of NN

    Returns
      feed_dict: a dictionary that can be used in TF run.
    """
    if isinstance(batch, PairData):
        func_data = batch
        labels = None
    else:
        func_data, labels = batch

    feed_dict = {
        placeholders["x_1"]: func_data.x_1,
        placeholders["x_2"]: func_data.x_2,
        placeholders["adj_1"]: func_data.adj_1,
        placeholders["adj_2"]: func_data.adj_2,
    }

    # lengths placeholders must be set only for RNN network type
    if network_type == "rnn":
        feed_dict[placeholders["lengths_1"]] = func_data.lengths_1
        feed_dict[placeholders["lengths_2"]] = func_data.lengths_2

    # Set the labels only if provided in the input batch data.
    if labels is not None:
        feed_dict[placeholders["labels"]] = labels

    return feed_dict
