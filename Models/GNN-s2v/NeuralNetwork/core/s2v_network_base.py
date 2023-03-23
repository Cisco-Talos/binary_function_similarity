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

from .model_evaluation import auc

log = logging.getLogger("s2v")


class BaseMeanFieldNetwork:
    """GNN with MeanField (structure2vec) message passing."""

    def __init__(self, config, bb_features_size):
        self.bb_features_size = bb_features_size

        self.learning_rate = config["training"]["learning_rate"]
        self.l2_reg_lambda = config["l2_reg_lambda"]

        self.max_lv = config["max_lv"]
        self.T_iterations = config["T_iterations"]

        self.embedding_size = config["embedding_size"]
        return

    def meanField(self, input_x, input_adj, name):
        """
        This is an implementation of the Embedded Mean Field (aka vanilla)
        algorithm from structure2vec paper: "Discriminative Embeddings of
        Latent Variable Models for Structured Data",
        Hanjun Dai, Bo Dai, Le Song

        pytorch structure2vec code :
        https://github.com/Hanjun-Dai/pytorch_structure2vec/blob/
        bcf20c90f21e468f862f13e2f5809a52cd247d4e/s2v_lib/embedding.py#L54

        Note: There are some minor differences with the code from above,
        but the implementation is consistent with what is described in the
        BAR paper.

        Note2: The graph is directed, and for the message passing the
        adjancency matrix is used to compute a summary of the graph.
        In the following algorithms the messages goes from the destination
        toward the source; if the opposite behaviour is required, use the
        transpose of the input_adj matrix.

        Args
            input_x: feature matrix
            input_adj: adjacency matrix
            name: TF name of the meanField operation (deubg only)

        Return
            the graph embedding for the input matrix
        """

        # Tiled matrices are 3d tensors: 2d matrix + one dimension for the
        # batch size. Process in one shot all the batch size graphs.
        # E.g., if you have M1 [batch_size, n, m] and M2 [batch_size, m, k],
        # tf.matmul(M1, M2) returns [batch_size, n, k]

        # b: batch size
        # d: number of features associated to each vertex
        # p: embedding dimension
        # vv: number of vertices in the graph

        # W1 is a [b, d, p] matrix
        W1_tiled = tf.tile(
            tf.expand_dims(self.W1, 0),
            [tf.shape(input_x)[0], 1, 1],
            name=name + "_W1_tiled",
        )

        # W2 is a [b, p, p] matrix
        W2_tiled = tf.tile(
            tf.expand_dims(self.W2, 0),
            [tf.shape(input_x)[0], 1, 1],
            name=name + "_W2_tiled",
        )

        # This list contains the weight matrices from the non
        # linear function that processes the messages from
        # neighbor nodes. These are called P1, P2,... Pl in the paper.
        CONV_PARAMS_tiled = []
        for lv in range(self.max_lv):
            CONV_PARAMS_tiled.append(
                tf.tile(
                    tf.expand_dims(self.CONV_PARAMS[lv], 0),
                    [tf.shape(input_x)[0], 1, 1],
                    name=name + "_CONV_PARAMS_tiled_" + str(lv),
                )
            )

        # input_x x W1 = [b, vv, d] x [b, d, p]
        # w1xv = [b, vv, p] --> each vertex has a p-len vector associated
        w1xv = tf.matmul(input_x, W1_tiled, name=name + "_w1xv")

        # Smart way to compute the sum of the p-vectors for neighbor nodes.
        # input_adj x w1xv = [b, vv, vv] x [b, vv, p]
        # l_mat = [b, vv, p] --> each vertex has a p-len vector associated.
        # Given that matrix multiplication is a row by column operation, each
        # row corresponds to a vertex, and 0/1 values act as a bitmask on the
        # p-vectors of the neighbors of each vertex.
        l_mat = tf.matmul(input_adj, w1xv, name=name + "_l_iteration" + str(1))

        out = w1xv

        # Iterations for the message passing
        for i in range(self.T_iterations - 1):
            # Compute the non-linearity from the messages
            # of neighbor nodes (l_mat)
            ol = l_mat
            lv = self.max_lv - 1
            while lv >= 0:
                with tf.name_scope("cell_" + str(lv)):
                    # Pi matrix multiplication
                    # ol x Pi = [b, vv, p] x [b, p, p]
                    # node_linear = [b, vv, p]
                    node_linear = tf.matmul(
                        ol, CONV_PARAMS_tiled[lv], name=name + "_conv_params_" + str(lv)
                    )

                    # if it's not the output layer, apply the ReLU function.
                    if lv > 0:
                        ol = tf.nn.relu(node_linear, name=name + "_relu_" + str(lv))
                    else:
                        # last layer
                        ol = node_linear
                lv -= 1

            # Get the tanh (number in range of -1, 1) from the sum of
            # w1xv (current vertex embedding) and ol (neighbor embeddings)
            out = tf.nn.tanh(w1xv + ol, name=name + "_mu_iteration" + str(i + 2))

            # Update l_mat, the matrix with the neighbors contributions for
            # each node. See the explanation above.
            l_mat = tf.matmul(input_adj, out, name=name + "_l_iteration" + str(i + 2))

        # Sum the embedding associate to each vertex, resulting in an
        # unique embedding for the entire graph.
        # f1 = [b, 1, p]
        fi = tf.expand_dims(
            tf.reduce_sum(out, axis=1, name=name + "_y_potential_reduce_sum"),
            axis=1,
            name=name + "_y_potential_expand_dims",
        )

        # f1 x W2 = [b, 1, p] x [b, p, p]
        # graph_embedding = [b, 1, p]
        graph_embedding = tf.matmul(fi, W2_tiled, name=name + "_graph_embedding")

        return graph_embedding

    def build_placeholders(self):
        """Build the placeholders needed for the model.

        Returns
          placeholders: a placeholder name -> placeholder tensor dict.
        """
        self.placeholders = dict()
        return

    def generateGraphClassificationNetwork(self, x_1_input, x_2_input):
        norms = []  # Just for debug/logging
        l2_loss = tf.constant(0.0)

        with tf.name_scope("parameters_MeanField"):
            # W1 is a [d,p] matrix, p is the embedding size
            self.W1 = tf.Variable(
                tf.random.truncated_normal(
                    [self.bb_features_size, self.embedding_size], stddev=0.1
                ),
                name="W1",
            )
            norms.append(tf.norm(self.W1))

            # CONV_PARAMSi (i=1,...,n) is a [p,p] matrix.
            # n is the neural network depth (self.max_lv)
            self.CONV_PARAMS = []
            for lv in range(self.max_lv):
                v = tf.Variable(
                    tf.random.truncated_normal(
                        [self.embedding_size, self.embedding_size], stddev=0.1
                    ),
                    name="CONV_PARAMS_" + str(lv),
                )
                self.CONV_PARAMS.append(v)
                norms.append(tf.norm(v))

            # W2 is another [p,p] matrix
            self.W2 = tf.Variable(
                tf.random.truncated_normal(
                    [self.embedding_size, self.embedding_size], stddev=0.1
                ),
                name="W2",
            )
            norms.append(tf.norm(self.W2))

        # Mean Field - structure2vec implementation
        with tf.name_scope("MeanField1"):
            graph_embedding_1 = tf.nn.l2_normalize(
                tf.squeeze(
                    self.meanField(x_1_input, self.placeholders["adj_1"], "MeanField1"),
                    axis=1,
                ),
                axis=1,
                name="embedding1",
            )

        with tf.name_scope("MeanField2"):
            graph_embedding_2 = tf.nn.l2_normalize(
                tf.squeeze(
                    self.meanField(x_2_input, self.placeholders["adj_2"], "MeanField2"),
                    axis=1,
                ),
                axis=1,
                name="embedding2",
            )

        with tf.name_scope("Siamese"):
            cos_similarity = tf.reduce_sum(
                tf.multiply(graph_embedding_1, graph_embedding_2),
                axis=1,
                name="cosSimilarity",
            )

            pair_auc = auc(cos_similarity, self.placeholders["labels"])

        # Regularization
        with tf.name_scope("Regularization"):
            l2_loss += tf.nn.l2_loss(self.W1)
            for lv in range(self.max_lv):
                l2_loss += tf.nn.l2_loss(self.CONV_PARAMS[lv])
            l2_loss += tf.nn.l2_loss(self.W2)

        # Least squared loss
        with tf.name_scope("Loss"):
            loss = tf.reduce_sum(
                tf.math.squared_difference(cos_similarity, self.placeholders["labels"]),
                name="loss",
            )

            # L2 regularization to prevent overfitting
            regularized_loss = loss + self.l2_reg_lambda * l2_loss

        # Train step (minimize the loss)
        with tf.name_scope("Train_Step"):
            train_step = tf.compat.v1.train.AdamOptimizer(self.learning_rate).minimize(
                regularized_loss
            )

        # Output tensors
        self.tensors = {
            "train_step": train_step,
            "metrics": {
                "training": {
                    "loss": loss,
                    "regularized_loss": regularized_loss,
                    "norms": norms,
                },
                "evaluation": {
                    "pair_similarity": cos_similarity,
                    "pair_labels": self.placeholders["labels"],
                    "pair_auc": pair_auc,
                },
            },
            "embeddings": {
                "embedding_1": graph_embedding_1,
                "embedding_2": graph_embedding_2,
            },
        }
