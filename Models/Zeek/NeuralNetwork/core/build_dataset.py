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
#  Zeek Neural Network                                                       #
#                                                                            #
##############################################################################

from .pair_factory_testing import PairFactoryTesting
from .pair_factory_inference import PairFactoryInference
from .pair_factory_training import PairFactoryTraining
from .pair_factory_base import JoinedPairData

import logging
log = logging.getLogger('zeek')


def build_train_val_test_generators(config):
    """Utility function to build all the generator by once.

    Args
      config: global configuration
    """
    training_set = build_random_batch_generator(
        config,
        config['training']['df_train_path'],
        config['training']['features_train_path'])

    validation_set = build_batch_generator(
        config,
        config['validation']['positive_path'],
        config['validation']['negative_path'],
        config['validation']['features_validation_path'])

    testing_set = build_batch_generator(
        config,
        config['testing']['positive_path'],
        config['testing']['negative_path'],
        config['testing']['features_testing_path'])

    return training_set, validation_set, testing_set


def build_random_batch_generator(config, df_path, feat_path):
    """Build a random batch_generator with positive and negative pairs.

    Args
      config: global configuration
      df_path: CSV file with functions information
      feat_path: JSON with features associated to each function
    """
    batch_generator = PairFactoryTraining(
        df_path=df_path,
        feat_path=feat_path,
        batch_size=config['batch_size'],
        vector_size=config['vector_size']
    )

    return batch_generator


def build_batch_generator(config, pos_path, neg_path, feat_path):
    """Build a batch_generator with positive and negative pairs.

    Args
      config: global configuration
      pos_path: positive csv path
      neg_path: negative csv path
      feat_path: JSON with features associated to each function
    """
    batch_generator = PairFactoryTesting(
        positive_path=pos_path,
        negative_path=neg_path,
        feat_path=feat_path,
        batch_size=config['batch_size'],
        vector_size=config['vector_size'],)

    return batch_generator


def build_single_batch_generator(config, csv_path, feat_path):
    """Build a batch_generator from the csv in input.

    Args
      config: global configuration
      csv_path: csv input path
      feat_path: JSON with features associated to each function
    """
    batch_generator = PairFactoryInference(
        df_path=csv_path,
        feat_path=feat_path,
        batch_size=config['batch_size'],
        vector_size=config['vector_size'],)

    return batch_generator


def fill_feed_dict(placeholders, batch):
    """Create a feed dict for the given batch of data.

    Args
      placeholders: a dict of placeholders as defined zeek_network.py
      batch: a batch of data, should be either a single `JoinedPairData`
        instance for triplet training or sigle batch evaluation,
        or a tuple of (pair, labels) for pairwise training.

    Returns
      feed_dict: a dictionary that can be used in TF run feed_dict arg.
    """
    # Triplet training or single batch evaluation
    if isinstance(batch, JoinedPairData):
        pair = batch
        labels = None
    else:
        pair, labels = batch

    feed_dict = {
        placeholders['x']: pair.x
    }

    # Set the labels only if provided in the input batch data.
    if labels is not None:
        feed_dict[placeholders['labels']] = labels

    return feed_dict
