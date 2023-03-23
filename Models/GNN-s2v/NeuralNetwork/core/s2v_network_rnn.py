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
#  This implementation contains code from:                                   #
#  https://github.com/lucamassarelli/Unsupervised-Features-Learning-         #
#    For-Binary-Similarity licensed under CC BY-NC-SA 4.0.                   #
#                                                                            #
##############################################################################

import numpy as np
import tensorflow as tf
import logging

from .s2v_network_base import BaseMeanFieldNetwork

log = logging.getLogger("s2v")


class RnnNetwork(BaseMeanFieldNetwork):
    """RNN"""

    def __init__(self, config, embedding_matrix):
        super(RnnNetwork, self).__init__(config, np.shape(embedding_matrix)[1])
        self.rnn_depth = config["rnn_depth"]
        self.rnn_kind = config["rnn_kind"]
        self.trainable_embeddings = config["trainable_embeddings"]
        self.embedding_matrix = embedding_matrix
        self.create_network()

    def extract_axis_1(self, data, ind):
        """
        Get specified elements along the first axis of tensor.
        :param data: Tensorflow tensor that will be subsetted.
        :param ind: Indices to take (one for each element
            along axis 0 of data).
        :return: Subsetted tensor.
        """
        ind = tf.nn.relu(ind - 1)
        batch_range = tf.range(tf.shape(data)[0])
        indices = tf.stack([batch_range, ind], axis=1)
        res = tf.gather_nd(data, indices)

        return res

    def lstmFeatures(self, input_x, lengths):
        flattened_inputs = tf.reshape(
            input_x, [-1, tf.shape(input_x)[2]], name="Flattening"
        )

        flattened_lengths = tf.reshape(lengths, [-1])
        max = tf.reduce_max(flattened_lengths)
        flattened_inputs = flattened_inputs[:, :max]

        flattened_embedded = tf.nn.embedding_lookup(
            self.instruction_embeddings_t, flattened_inputs
        )

        zeros = tf.zeros(tf.shape(flattened_lengths)[0], dtype=tf.int32)
        mask = tf.not_equal(flattened_lengths, zeros)
        int_mask = tf.cast(mask, tf.int32)
        fake_output = tf.zeros([self.bb_features_size], dtype=tf.float32)
        partitions = tf.dynamic_partition(flattened_embedded, int_mask, 2)
        real_nodes = partitions[1]
        real_lengths = tf.boolean_mask(flattened_lengths, mask)
        fake_zero = tf.tile(
            [fake_output],
            [tf.shape(flattened_embedded)[0] - tf.shape(partitions[1])[0], 1],
        )

        if self.rnn_kind == 0:
            rnn_layers = [
                tf.nn.rnn_cell.LSTMCell(size)
                for size in ([self.bb_features_size] * self.rnn_depth)
            ]

        else:
            rnn_layers = [
                tf.nn.rnn_cell.GRUCell(size)
                for size in ([self.bb_features_size] * self.rnn_depth)
            ]

        cell = tf.nn.rnn_cell.MultiRNNCell(rnn_layers)

        rnn_outputs, _ = tf.nn.dynamic_rnn(
            cell,
            real_nodes,
            sequence_length=real_lengths,
            dtype=tf.float32,
            time_major=False,
            parallel_iterations=88,
        )

        last_outputs = self.extract_axis_1(rnn_outputs, real_lengths)

        condition_indices = tf.dynamic_partition(
            tf.range(tf.shape(flattened_embedded)[0]), int_mask, 2
        )

        last_outputs = tf.dynamic_stitch(condition_indices, [fake_zero, last_outputs])

        print("shape: " + str(tf.shape(last_outputs)))

        gather_output2 = tf.reshape(
            last_outputs,
            [-1, tf.shape(input_x)[1], self.bb_features_size],
            name="Deflattening",
        )

        output = tf.identity(gather_output2, name="LSTMOutput")
        output = tf.nn.l2_normalize(output)
        return output

    def build_placeholders(self):
        """Build the placeholders needed for the model.

        Returns
          placeholders: a placeholder name -> placeholder tensor dict.
        """
        self.placeholders = {
            "x_1": tf.compat.v1.placeholder(tf.int32, [None, None, None], name="x_1"),
            "adj_1": tf.compat.v1.placeholder(
                tf.float32, [None, None, None], name="adj_1"
            ),
            "lengths_1": tf.compat.v1.placeholder(
                tf.int32, [None, None], name="lengths_1"
            ),
            "x_2": tf.compat.v1.placeholder(tf.int32, [None, None, None], name="x_2"),
            "adj_2": tf.compat.v1.placeholder(
                tf.float32, [None, None, None], name="adj_2"
            ),
            "lengths_2": tf.compat.v1.placeholder(
                tf.int32, [None, None], name="lengths_2"
            ),
            "labels": tf.compat.v1.placeholder(tf.float32, [None], name="labels"),
        }
        return

    def create_network(self):
        """Wrapper function around generateGraphClassificationNetwork."""
        self.build_placeholders()

        self.instruction_embeddings_t = tf.Variable(
            initial_value=tf.constant(self.embedding_matrix),
            trainable=self.trainable_embeddings,
            name="instruction_embedding",
            dtype=tf.float32,
        )

        # LSTMExtraction
        with tf.name_scope("LSTMExtraction1"):
            with tf.compat.v1.variable_scope("lstm1"):
                self.x_1_after_lstm = self.lstmFeatures(
                    self.placeholders["x_1"], self.placeholders["lengths_1"]
                )

        with tf.name_scope("LSTMExtraction2"):
            with tf.compat.v1.variable_scope("lstm2"):
                self.x2_after_lstm = self.lstmFeatures(
                    self.placeholders["x_2"], self.placeholders["lengths_2"]
                )

        self.generateGraphClassificationNetwork(self.x_1_after_lstm, self.x2_after_lstm)
