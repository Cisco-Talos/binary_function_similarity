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


import collections
import numpy as np
import os
import pandas as pd
import random
import tensorflow as tf
import time

from .build_dataset import *
from .model_evaluation import *
from .zeek_network import ZeekNetwork

import logging
log = logging.getLogger('zeek')


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


class ZeekModel:

    def __init__(self, config):
        """
        ZeekModel initialization

        Args
            config: global configuration
        """
        self._config = config
        self._model_name = "zeek"

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
        self._network = ZeekNetwork(self._config)

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
        log.info("Loading trained model from: %s", latest_checkpoint)
        self._tf_saver.restore(self._session, latest_checkpoint)
        return

    def _run_evaluation(self, batch_generator):
        """
        Common operations for the dataset evaluation.
        Used with validation and testing.

        Args
            batch_generator: a function generator for the dataset in input.
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
            log.info("\t\t%s - auc: %.4f", item[0], item[1])

        return evaluation_metrics['avg_pair_auc']

    def model_train(self, restore):
        """
        Zeek train
        """
        # Create a training and validation dataset
        training_set, validation_set, testing_set = \
            build_train_val_test_generators(self._config)

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
        self._run_evaluation(testing_set)

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

            log.info("Testing set")
            self._run_evaluation(testing_set)

            # Save the model
            self._tf_saver.save(
                self._session,
                self._checkpoint_path,
                global_step=it_num)
            log.info("Model saved: %s" % self._checkpoint_path)

        if self._session:
            self._session.close()
        return

    def model_evaluate(self):
        """Test the trained model with the evaluation and testing datasets"""

        # Create a training and validation dataset
        _, validation_set, testing_set = \
            build_train_val_test_generators(self._config)

        # Model initialization
        self._model_initialize()

        # Model restoring
        self._create_tfsaver()
        self._restore_model()

        # Evaluate the validation set
        self._run_evaluation(validation_set)

        # Evaluate the testing set
        self._run_evaluation(testing_set)

        if self._session:
            self._session.close()
        return

    def model_test(self):
        """Testing Zeek model on a single CSV with function pairs"""

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

            batch_generator = build_single_batch_generator(
                self._config,
                df_input_path,
                self._config['testing']['features_testing_path'])

            similarity_list = evaluate_sim(
                self._session,
                self._network.tensors['metrics']['evaluation'],
                self._network.placeholders,
                batch_generator)

            # Save the cosine similarity
            df['sim'] = similarity_list[:df.shape[0]]

            # Save the df to CSV
            df.to_csv(df_output_path)
            log.info("Result df saved to %s", df_output_path)

        if self._session:
            self._session.close()
        return
