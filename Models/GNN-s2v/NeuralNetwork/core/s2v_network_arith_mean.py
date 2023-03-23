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


class ArithMeanNetwork(BaseMeanFieldNetwork):
    """Arith mean"""

    def __init__(self, config, embedding_matrix):
        super(ArithMeanNetwork, self).__init__(
            config,
            # embedding_size
            np.shape(embedding_matrix)[1],
        )
        self.length_raw_features = config["length_raw_features"]
        self.trainable_embeddings = config["trainable_embeddings"]
        self.embedding_matrix = embedding_matrix
        self.create_network()

    def node_features_aggregator(self, input_x):
        flattened_inputs = tf.reshape(
            input_x, [-1, tf.shape(input_x)[2]], name="Flattening"
        )

        flattened_embedded = tf.nn.embedding_lookup(
            self.instruction_embeddings_t, flattened_inputs
        )

        last_outputs = tf.squeeze(
            tf.nn.l2_normalize(
                tf.reduce_mean(flattened_embedded, name="arith_mean", axis=1), axis=1
            )
        )

        gather_output2 = tf.reshape(
            last_outputs,
            [-1, tf.shape(input_x)[1], self.bb_features_size],
            name="Deflattening",
        )

        output = tf.identity(gather_output2, name="NodeAggregationOutput")
        output = tf.nn.l2_normalize(output)
        return output

    def build_placeholders(self):
        """Build the placeholders needed for the model.

        Returns
          placeholders: a placeholder name -> placeholder tensor dict.
        """
        self.placeholders = {
            "x_1": tf.compat.v1.placeholder(
                tf.int32, [None, None, self.length_raw_features], name="x_1"
            ),
            "adj_1": tf.compat.v1.placeholder(
                tf.float32, [None, None, None], name="adj_1"
            ),
            "x_2": tf.compat.v1.placeholder(
                tf.int32, [None, None, self.length_raw_features], name="x_2"
            ),
            "adj_2": tf.compat.v1.placeholder(
                tf.float32, [None, None, None], name="adj_2"
            ),
            "labels": tf.compat.v1.placeholder(tf.float32, [None], name="labels"),
        }
        return

    def create_network(self):
        """
        Wrapper function around generateGraphClassificationNetwork.
        """
        self.build_placeholders()

        self.instruction_embeddings_t = tf.Variable(
            initial_value=tf.constant(self.embedding_matrix),
            trainable=self.trainable_embeddings,
            name="instruction_embedding",
            dtype=tf.float32,
        )

        # Node features aggregation
        with tf.name_scope("NodeFeaturesAggregator1"):
            with tf.compat.v1.variable_scope("aggregation1"):
                self.x_1_after_aggregation = self.node_features_aggregator(
                    self.placeholders["x_1"]
                )

        with tf.name_scope("NodeFeaturesAggregator2"):
            with tf.compat.v1.variable_scope("aggregation2"):
                self.x2_after_aggregation = self.node_features_aggregator(
                    self.placeholders["x_2"]
                )

        self.generateGraphClassificationNetwork(
            self.x_1_after_aggregation, self.x2_after_aggregation
        )
