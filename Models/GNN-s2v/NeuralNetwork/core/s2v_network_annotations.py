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

import tensorflow as tf
import logging

from .s2v_network_base import BaseMeanFieldNetwork

log = logging.getLogger("s2v")


class AnnotationsNetwork(BaseMeanFieldNetwork):
    """
    Reimplementation of the model presented in "Neural network-based graph
    embedding for cross-platform binary code similarity detection."
    """

    def __init__(self, config):
        super(AnnotationsNetwork, self).__init__(config, config["bb_features_size"])
        self.create_network()

    def build_placeholders(self):
        """Build the placeholders needed for the model.

        Returns
          placeholders: a dictionary that maps placeholder names
            to tensors.
        """
        self.placeholders = {
            # 3d tensor: [batch_size, number_of_vertices, feature_size]
            # Even if node features (x_1) are integers, they need to be defined
            # as float32 since they are directly multiplied with W1 which is a
            # float32 matrix.
            "x_1": tf.compat.v1.placeholder(
                tf.float32, [None, None, self.bb_features_size], name="x_1"
            ),
            # 3d tensor: [batch_size, number_of_vertices, number_of_vertices]
            "adj_1": tf.compat.v1.placeholder(
                tf.float32, [None, None, None], name="adj_1"
            ),
            "x_2": tf.compat.v1.placeholder(
                tf.float32, [None, None, self.bb_features_size], name="x_2"
            ),
            "adj_2": tf.compat.v1.placeholder(
                tf.float32, [None, None, None], name="adj_2"
            ),
            # [batch_size]
            "labels": tf.compat.v1.placeholder(tf.float32, [None], name="labels"),
        }
        return

    def create_network(self):
        """
        Wrapper function around generateGraphClassificationNetwork.
        """
        self.build_placeholders()
        self.generateGraphClassificationNetwork(
            self.placeholders["x_1"], self.placeholders["x_2"]
        )
