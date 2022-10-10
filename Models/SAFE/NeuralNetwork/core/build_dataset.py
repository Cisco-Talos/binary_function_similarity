##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  This program is free software: you can redistribute it and/or modify      #
#  it under the terms of the GNU General Public License as published by      #
#  the Free Software Foundation, either version 3 of the License, or         #
#  (at your option) any later version.                                       #
#                                                                            #
#  This program is distributed in the hope that it will be useful,           #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of            #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
#  GNU General Public License for more details.                              #
#                                                                            #
#  You should have received a copy of the GNU General Public License         #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.    #
#                                                                            #
#  SAFE Neural Network                                                       #
#                                                                            #
#  This implementation contains code from                                    #
#  https://github.com/gadiluna/SAFE licensed under GPL-3.0                   #
#                                                                            #
##############################################################################

from .pair_factory_base import PairData
from .pair_factory_inference import PairFactoryInference
from .pair_factory_testing import PairFactoryTesting
from .pair_factory_training import PairFactoryTraining

import logging
log = logging.getLogger('safe')


def build_train_validation_generators(config):
    """Utility function to build train and validation batch generators.

    Args
      config: global configuration
    """
    training_gen = PairFactoryTraining(
        func_path=config['training']['df_train_path'],
        feat_path=config['training']['features_train_path'],
        batch_size=config['batch_size'],
        max_ins=config['max_instructions']
    )

    validation_gen = PairFactoryTesting(
        pos_path=config['validation']['positive_path'],
        neg_path=config['validation']['negative_path'],
        feat_path=config['validation']['features_validation_path'],
        batch_size=config['batch_size'],
        max_ins=config['max_instructions'])

    return training_gen, validation_gen


def build_testing_generator(config, csv_path):
    """Build a batch_generator from the CSV in input.

    Args
      config: global configuration
      csv_path: CSV input path
    """
    testing_gen = PairFactoryInference(
        func_path=csv_path,
        feat_path=config['testing']['features_testing_path'],
        batch_size=config['batch_size'],
        max_ins=config['max_instructions']
    )
    return testing_gen


def fill_feed_dict(placeholders, batch):
    """Create a feed dict for the given batch of data.

    Args
      placeholders: a dict of placeholders as defined in safe_network.py
      batch: a batch of data, should be either a single `PairData`
        instance for triplet training or single batch evaluation,
        or a tuple of (func_data, labels) for pairwise training.

    Returns
      feed_dict: a dictionary that can be used in TF run.
    """
    if isinstance(batch, PairData):
        func_data = batch
        labels = None
    else:
        func_data, labels = batch

    feed_dict = {
        placeholders['x_1']: func_data.x_1,
        placeholders['x_2']: func_data.x_2,
        placeholders['lengths_1']: func_data.lengths_1,
        placeholders['lengths_2']: func_data.lengths_2
    }

    # Set the labels only if provided in the input batch data.
    if labels is not None:
        feed_dict[placeholders['labels']] = labels

    return feed_dict
