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

import collections
import numpy as np
import os
import pandas as pd
import random
import tensorflow as tf
import time

from .build_dataset import *
from .build_model import *
from .model_evaluation import *

import logging
log = logging.getLogger('gnn')


def _it_check_condition(it_num, threshold):
    """
    Utility function to make the code cleaner.

    Args:
        it_num: the iteration number.
        threshold: threshold at which the condition must be verfied.

    Return:
        True if it_num +1 is a multiple of the threshold.
    """
    return (it_num + 1) % threshold == 0


class GNNModel:

    def __init__(self, config):
        """
        GNNModel initialization

        Args:
            config: global configuration
        """
        self._config = config
        self._model_name = self._get_model_name()

        # Set random seeds
        seed = config['seed']
        random.seed(seed)
        np.random.seed(seed + 1)
        return

    def _get_model_name(self):
        """Return the name of the model based to the configuration."""
        model_type = self._config['model_type']
        training_mode = self._config['training']['mode']
        model_name = "graph-{}-{}".format(model_type, training_mode)
        return model_name

    def _get_debug_str(self, accumulated_metrics):
        """Return a string with the mean of the input values"""
        metrics_to_print = {k: np.mean(v)
                            for k, v in accumulated_metrics.items()}
        info_str = ', '.join([' %s %.4f' % (k, v)
                              for k, v in metrics_to_print.items()])
        return info_str

    def _create_network(self, batch_generator, is_training):
        """Build the model and set _tensors, _placeholders and _model."""
        # Automatically infer the node and edge features dim.

        _it = None
        if is_training and self._config['training']['mode'] == 'triplet':
            _it = batch_generator.triplets()
        else:
            _it = batch_generator.pairs()

        first_batch_graphs = None
        if is_training and self._config['training']['mode'] == 'pair':
            first_batch_graphs, _ = next(_it)
        else:
            first_batch_graphs = next(_it)

        # Set the feature dimensions
        node_feature_dim = first_batch_graphs.node_features.shape[-1]
        edge_feature_dim = first_batch_graphs.edge_features.shape[-1]
        log.info("node_feature_dim: %d", node_feature_dim)
        log.info("edge_feature_dim: %d", edge_feature_dim)

        self._tensors, self._placeholders, self._model = build_model(
            self._config, node_feature_dim, edge_feature_dim)
        return

    def _model_initialize(self, batch_generator, is_training=True):
        """Create TF session, build the model, initialize TF variables"""
        tf.compat.v1.reset_default_graph()

        session_conf = tf.compat.v1.ConfigProto(
            allow_soft_placement=True,
            log_device_placement=False)

        self._session = tf.compat.v1.Session(config=session_conf)

        # Note: tf.compat.v1.set_random_seed sets the graph-level TF seed.
        # Results will be still different from one run to the other because
        # tf.random operations relies on an operation specific seed.
        tf.compat.v1.set_random_seed(self._config['seed'] + 2)

        # Create the TF NN
        self._create_network(batch_generator, is_training=is_training)

        # Initialize all the variables
        init_ops = (tf.compat.v1.global_variables_initializer(),
                    tf.compat.v1.local_variables_initializer())
        self._session.run(init_ops)
        return

    def _create_tfsaver(self):
        """Create a TF saver for model checkpoint"""
        self._tf_saver = tf.compat.v1.train.Saver()
        checkpoint_dir = self._config['checkpoint_dir']
        self._checkpoint_path = os.path.join(checkpoint_dir, self._model_name)
        return

    def _restore_model(self):
        """Restore the model from the latest checkpoint"""
        checkpoint_dir = self._config['checkpoint_dir']
        latest_checkpoint = tf.train.latest_checkpoint(checkpoint_dir)
        log.info("Loading trained model from: {}".format(latest_checkpoint))
        self._tf_saver.restore(self._session, latest_checkpoint)
        return

    def _run_evaluation(self, batch_generator):
        """
        Common operations for the dataset evaluation.
        Used with validation and testing.

        Args:
            batch_generator: provides batches of input data.
        """
        evaluation_metrics = evaluate(
            self._session,
            self._tensors['metrics']['evaluation'],
            self._placeholders,
            batch_generator)

        log.info("pair_auc (avg over batches): %.4f" %
                 evaluation_metrics['pair_auc'])

        # Print the AUC for each DB type
        for item in evaluation_metrics['pair_auc_list']:
            log.info("\t\t%s - AUC: %.4f", item[0], item[1])

        return evaluation_metrics['pair_auc']

    def _initialize_bg(self, batch_generator):
        """Re-initialize the batch-generator"""
        if self._config['training']['mode'] == 'pair':
            return batch_generator.pairs()
        return batch_generator.triplets()

    def model_train(self, restore):
        """Run model training"""

        # Create a training and validation dataset
        training_set, validation_set = \
            build_train_validation_generators(self._config)

        # Model initialization
        self._model_initialize(training_set)

        # Model restoring
        self._create_tfsaver()
        if restore:
            self._restore_model()

        # Logging
        print_after = self._config['training']['print_after']

        log.info("Starting model training!")

        t_start = time.time()

        best_val_auc = 0
        accumulated_metrics = collections.defaultdict(list)

        # Iterates over the training data.
        it_num = 0

        # Let's check the starting values
        self._run_evaluation(validation_set)

        for epoch_counter in range(self._config['training']['num_epochs']):
            log.info("Epoch %d", epoch_counter)

            # Batch generator in triplet or pair mode.
            training_batch_generator = self._initialize_bg(training_set)

            for training_batch in training_batch_generator:
                # TF Training step
                _, train_metrics = self._session.run([
                    self._tensors['train_step'],
                    self._tensors['metrics']['training']],
                    feed_dict=fill_feed_dict(
                        self._placeholders,
                        training_batch))

                # Accumulate over minibatches to reduce variance
                for k, v in train_metrics.items():
                    accumulated_metrics[k].append(v)

                # Logging
                if _it_check_condition(it_num, print_after):

                    # Print the AVG for each metric
                    info_str = self._get_debug_str(accumulated_metrics)
                    elapsed_time = time.time() - t_start
                    log.info('Iter %d, %s, time %.2fs' %
                             (it_num + 1, info_str, elapsed_time))

                    # Reset
                    accumulated_metrics = collections.defaultdict(list)

                it_num += 1

            # Run the evaluation at the end of each epoch:
            log.info("End of Epoch %d (elapsed_time %.2fs)",
                     epoch_counter, elapsed_time)

            log.info("Validation set")
            val_auc = self._run_evaluation(validation_set)
            if val_auc > best_val_auc:
                best_val_auc = val_auc
                log.warning("best_val_auc: %.4f", best_val_auc)

            # Save the model
            self._tf_saver.save(
                self._session,
                self._checkpoint_path,
                global_step=it_num)
            log.info("Model saved: {}".format(self._checkpoint_path))

        if self._session:
            self._session.close()
        return

    def model_validate(self):
        """Run model validation"""

        # Create a training and validation dataset
        training_set, validation_set = \
            build_train_validation_generators(self._config)

        # Model initialization
        self._model_initialize(training_set, is_training=False)

        # Model restoring
        self._create_tfsaver()
        self._restore_model()

        # Evaluate the validation set
        self._run_evaluation(validation_set)

        if self._session:
            self._session.close()
        return

    def model_test(self):
        """Testing the GNN model on a single CSV with function pairs"""

        # Model initialization
        batch_generator = build_testing_generator(
            self._config,
            self._config['testing']['full_tests_inputs'][0])

        self._model_initialize(batch_generator, is_training=False)

        # Model restoring
        self._create_tfsaver()
        self._restore_model()

        # Evaluate the full testing dataset
        for df_input_path, df_output_path in \
            zip(self._config['testing']['full_tests_inputs'],
                self._config['testing']['full_tests_outputs']):

            df = pd.read_csv(df_input_path, index_col=0)

            batch_generator = build_testing_generator(
                self._config,
                df_input_path)

            similarity_list = evaluate_sim(
                self._session,
                self._tensors['metrics']['evaluation'],
                self._placeholders,
                batch_generator)

            # Save the cosine similarity
            df['sim'] = similarity_list[:df.shape[0]]

            # Save the result to CSV
            df.to_csv(df_output_path)
            log.info("Result CSV saved to {}".format(df_output_path))

        if self._session:
            self._session.close()
        return
