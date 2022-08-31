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

import tensorflow as tf

from .model_evaluation import auc

import logging
log = logging.getLogger('zeek')


class ZeekNetwork():
    """
    Reimplementation of the Zeek Neural Network in TensorFlow
    """

    def __init__(self, config):
        self._config = config

        # Create the placeholders dict (input data)
        # self.placeholders

        # Create the tensor dict (output data)
        # self.tensors
        self.create_network(config)

    def build_placeholders(self):
        """Build the placeholders needed for the model.

        Args
          None

        Returns
          placeholders: a dictionary that maps placeholder names
            to tensors.
        """
        self.placeholders = {
            # 2d tensor: [batch_size, feature_size]
            # Even if features (x) are integers, they need to be defined
            # as float32 since they are directly multiplied with some
            # float32 matrix.
            'x': tf.compat.v1.placeholder(
                tf.float32,
                [None, self._config['nn_input_size']],
                name="x"),

            # 1d tensor: [batch_size]
            'labels': tf.compat.v1.placeholder(
                tf.float32,
                [None, 2],
                name='labels')
        }
        return

    def create_network(self, config):
        """
        Wrapper function around generateGraphClassificationNetwork.
        """
        self.build_placeholders()

        with tf.name_scope('FCNN'):
            h1 = tf.layers.dropout(
                tf.layers.dense(
                    inputs=self.placeholders['x'],
                    units=self._config['l1_size'],
                    activation=tf.nn.tanh),
                rate=self._config['dropout_reg'])

            h2 = tf.layers.dropout(
                tf.layers.dense(
                    inputs=h1,
                    units=self._config['l2_size'],
                    activation=tf.nn.tanh),
                rate=self._config['dropout_reg'])

            output = tf.layers.dense(
                inputs=h2,
                units=2)

            pair_similarity = tf.squeeze(
                tf.slice(
                    tf.nn.softmax(output),
                    [0, 0], [-1, 1]),
                axis=1)

            pair_labels = tf.squeeze(
                tf.slice(
                    self.placeholders['labels'],
                    [0, 0], [-1, 1]),
                axis=1)

            pair_auc = auc(
                pair_similarity,
                pair_labels)

        with tf.name_scope("Loss"):
            loss = tf.losses.softmax_cross_entropy(
                self.placeholders['labels'],
                output)

        with tf.name_scope("Train_Step"):
            train_step = tf.train.AdamOptimizer(
                self._config['training']['learning_rate']).minimize(
                loss)

        # Output tensors
        self.tensors = {
            'train_step': train_step,
            'metrics': {
                'training': {
                    'loss': loss,
                },
                'evaluation': {
                    'pair_similarity': pair_similarity,
                    'pair_labels': pair_labels,
                    'pair_auc': pair_auc

                },
            }
        }
