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
#  Gated Graph Sequence Neural Networks (GGSNN) and                          #
#    Graph Matching Networks (GMN) models implementation.                    #
#                                                                            #
#  This implementation contains code from:                                   #
#  https://github.com/deepmind/deepmind-research/blob/master/                #
#    graph_matching_networks/graph_matching_networks.ipynb                   #
#    licensed under Apache License 2.0                                       #
#                                                                            #
##############################################################################

from .graph_factory_testing import GraphFactoryTesting
from .graph_factory_inference import GraphFactoryInference
from .graph_factory_training import GraphFactoryTraining
from .graph_factory_base import GraphData

import logging
log = logging.getLogger('gnn')


def build_train_validation_generators(config):
    """Utility function to build train and validation batch generators.

    Args
      config: global configuration
    """
    training_gen = GraphFactoryTraining(
        func_path=config['training']['df_train_path'],
        feat_path=config['training']['features_train_path'],
        batch_size=config['batch_size'],
        use_features=config['data']['use_features'],
        features_type=config['features_type'],
        bb_features_size=config['bb_features_size'],
    )

    validation_gen = GraphFactoryTesting(
        pos_path=config['validation']['positive_path'],
        neg_path=config['validation']['negative_path'],
        feat_path=config['validation']['features_validation_path'],
        batch_size=config['batch_size'],
        use_features=config['data']['use_features'],
        features_type=config['features_type'],
        bb_features_size=config['bb_features_size'])

    return training_gen, validation_gen


def build_testing_generator(config, csv_path):
    """Build a batch_generator from the CSV in input.

    Args
      config: global configuration
      csv_path: CSV input path
    """
    testing_gen = GraphFactoryInference(
        func_path=csv_path,
        feat_path=config['testing']['features_testing_path'],
        batch_size=config['batch_size'],
        use_features=config['data']['use_features'],
        features_type=config['features_type'],
        bb_features_size=config['bb_features_size'])

    return testing_gen


def fill_feed_dict(placeholders, batch):
    """Create a feed dict for the given batch of data.

    Args:
      placeholders: a dict of placeholders as defined in build_model.py
      batch: a batch of data, should be either a single `GraphData`
        instance for triplet training, or a tuple of (graphs, labels)
        for pairwise training.

    Returns:
      feed_dict: a dictionary that can be used in TF run.
    """
    if isinstance(batch, GraphData):
        graphs = batch
        labels = None
    else:
        graphs, labels = batch

    feed_dict = {
        placeholders['node_features']: graphs.node_features,
        placeholders['edge_features']: graphs.edge_features,
        placeholders['from_idx']: graphs.from_idx,
        placeholders['to_idx']: graphs.to_idx,
        placeholders['graph_idx']: graphs.graph_idx,
    }

    # Set the labels only if provided in the input batch data.
    if labels is not None:
        feed_dict[placeholders['labels']] = labels
    return feed_dict
