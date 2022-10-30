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

import collections
import numpy as np
import os
import pandas as pd
import random
import sys
import tensorflow as tf
import time

from .build_dataset import *
from .model_evaluation import *
from .safe_network import SiameseSelfAttentive

import logging
log = logging.getLogger('safe')


def _it_check_condition(it_num, threshold):
    """
    Utility function to make the code cleaner.

    Args:
        it_num: the iteration number.
        threshold: threshold at which the condition must be verified.

    Return:
        True if it_num +1 is a multiple of the threshold.
    """
    return (it_num + 1) % threshold == 0


class SAFEModel:

    def __init__(self, config):
        """
        SAFEModel initialization

        Args
            config: global configuration
        """
        self._config = config
        self._model_name = "safe"

        # Set random seeds
        seed = config['seed']
        random.seed(seed)
        np.random.seed(seed + 1)
        return

    def _get_debug_str(self, accumulated_metrics):
        """Return a string with the mean of the input values"""
        metrics_to_print = {k: np.mean(v)
                            for k, v in accumulated_metrics.items()}
        info_str = ', '.join([' %s %.4f' % (k, v)
                              for k, v in metrics_to_print.items()])
        return info_str

    def _load_embedding_matrix(self):
        """Load the Numpy matrix of the instruction embeddings"""
        try:
            matrix_path = self._config['path_embedding_matrix']

            # Check if the matrix file exists
            if not os.path.isfile(matrix_path):
                raise Exception("Embedding matrix not found")

            log.debug('Loading embedding matrix....')
            with open(matrix_path, 'rb') as f:
                matrix = np.float32(np.load(f))
                log.debug('matrix shape: ', matrix.shape)

            if self._config['random_embeddings']:
                matrix = np.random.rand(*np.shape(matrix)).astype(np.float32)
                matrix[0, :] = np.zeros(np.shape(matrix)[1]).astype(np.float32)

            return matrix

        except Exception:
            log.exception("Embedding matrix loading error")
            # Non recoverable error.
            sys.exit(1)

    def _model_initialize(self):
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
        self._embedding_matrix = self._load_embedding_matrix()
        self._network = SiameseSelfAttentive(
            self._config, self._embedding_matrix)

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

        Args
            batch_generator: provides batches of input data.
        """
        evaluation_metrics = evaluate(
            self._session,
            self._network.tensors['metrics']['evaluation'],
            self._network.placeholders,
            batch_generator)

        log.info("pair_auc (avg over batches): %.4f" %
                 evaluation_metrics['avg_pair_auc'])

        # Print the AUC for each DB type
        for item in evaluation_metrics['pair_auc_dbtype_list']:
            log.info("\t\t%s - AUC: %.4f", item[0], item[1])

        return evaluation_metrics['avg_pair_auc']

    def model_train(self, restore):
        """Run model training"""

        # Create a training and validation dataset
        training_set, validation_set = \
            build_train_validation_generators(self._config)

        # Model initialization
        self._model_initialize()

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

            training_batch_generator = training_set.pairs()
            for training_batch in training_batch_generator:

                # TF Training step
                _, train_metrics = self._session.run([
                    self._network.tensors['train_step'],
                    self._network.tensors['metrics']['training']],
                    feed_dict=fill_feed_dict(
                        self._network.placeholders,
                        training_batch))

                # Accumulate over mini batches to reduce variance
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
        _, validation_set = \
            build_train_validation_generators(self._config)

        # Model initialization
        self._model_initialize()

        # Model restoring
        self._create_tfsaver()
        self._restore_model()

        # Evaluate the validation set
        self._run_evaluation(validation_set)

        if self._session:
            self._session.close()
        return

    def model_test(self):
        """Testing the SAFE model on a single CSV with function pairs"""

        # Model initialization
        self._model_initialize()

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
                self._network.tensors['metrics']['evaluation'],
                self._network.placeholders,
                batch_generator)

            # Save the cosine similarity
            df['sim'] = similarity_list[:df.shape[0]]

            # Save the result to CSV
            df.to_csv(df_output_path)
            log.info("Result CSV saved to {}".format(df_output_path))

        if self._session:
            self._session.close()
        return
