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

import tensorflow as tf
from .model_evaluation import auc


class SiameseSelfAttentive:

    def __init__(self, config, embedding_matrix):

        self._learning_rate = config['training']['learning_rate']
        self._l2_reg_lambda = config['training']['l2_reg_lambda']

        self._embedding_size = config['embedding_size']
        self._trainable_embeddings = config['trainable_embeddings']
        self._embedding_matrix = embedding_matrix

        self._rnn_depth = config['rnn_depth']
        self._max_instructions = config['max_instructions']
        self._rnn_state_size = config['rnn_state_size']
        self._dense_layer_size = config['dense_layer_size']

        self._attention_hops = config['attention_hops']
        self._attention_depth = config['attention_depth']

        self._create_model()
        return

    def _self_attentive_network(self, input_x, lengths):
        """
        Original code from SAFE (GPL-3.0):

        https://github.com/gadiluna/SAFE/blob/master/neural_network/SiameseSAFE.py
        """
        # Each function is a list of embeddings id
        # (indexes in the embeddings matrix)
        embbedded_functions = tf.nn.embedding_lookup(
            self.instructions_embeddings_t,
            input_x)

        # GRU RNN
        (output_fw, output_bw), _ = tf.nn.bidirectional_dynamic_rnn(
            self.cell_fw,
            self.cell_bw,
            embbedded_functions,
            sequence_length=lengths,
            dtype=tf.float32,
            time_major=False)

        # Matrix H
        H = tf.concat([output_fw, output_bw], axis=2)

        # We do a tile to account for training batches
        ws1_tiled = tf.tile(tf.expand_dims(self.WS1, 0),
                            [tf.shape(H)[0], 1, 1],
                            name="WS1_tiled")

        ws2_tile = tf.tile(tf.expand_dims(self.WS2, 0),
                           [tf.shape(H)[0], 1, 1],
                           name="WS2_tiled")

        # Matrix A
        self.A = tf.nn.softmax(
            tf.matmul(ws2_tile, tf.nn.tanh(
                tf.matmul(
                    ws1_tiled,
                    tf.transpose(H, perm=[0, 2, 1])))),
            name="Attention_Matrix")

        # Embedding matrix M
        M = tf.identity(
            tf.matmul(self.A, H),
            name="Attention_Embedding")

        # Flattened version of M
        flattened_M = tf.reshape(
            M,
            [tf.shape(M)[0], self._attention_hops * self._rnn_state_size * 2])

        return flattened_M

    def _create_model(self):

        # Used to keep track of the number of training steps
        self.global_step = tf.Variable(0, name='global_step', trainable=False)

        # Load the embedding matrix
        self.instructions_embeddings_t = tf.Variable(
            initial_value=tf.constant(self._embedding_matrix),
            trainable=self._trainable_embeddings,
            name="instructions_embeddings",
            dtype=tf.float32)

        # Example:
        # x_1=[[mov,add,padding,padding],[mov,mov,mov,padding]]
        # lenghts_1=[2,3]

        # The first dimension is the batch_size
        # List of instructions for Functions_in_list_1.
        # batch_size functions are processed together
        self.placeholders = {

            # self.x_1
            'x_1': tf.compat.v1.placeholder(
                tf.int32,
                [None, self._max_instructions],
                name="x_1"),

            # List of lengths for Functions_in_list_1.
            # self.lengths_1
            'lengths_1': tf.compat.v1.placeholder(
                tf.int32,
                [None],
                name='lengths_1'),

            # Same as before, but for Functions_in_list_2
            # self.x_2 =
            'x_2': tf.compat.v1.placeholder(
                tf.int32,
                [None, self._max_instructions],
                name="x_2"),

            # self.lengths_2 =
            'lengths_2': tf.compat.v1.placeholder(
                tf.int32,
                [None],
                name='lengths_2'),

            # Ground truth: +1 similar pairs, -1 dissimilar.
            # self.y =
            'labels': tf.compat.v1.placeholder(
                tf.float32,
                [None],
                name='y_')
        }

        # Euclidean norms; p = 2
        norms = []

        # Keeping track of l2 regularization loss (optional)
        l2_loss = tf.constant(0.0)

        with tf.name_scope('parameters_Attention'):
            self.WS1 = tf.Variable(
                tf.random.truncated_normal(
                    [self._attention_depth, 2 * self._rnn_state_size],
                    stddev=0.1),
                name="WS1")

            self.WS2 = tf.Variable(
                tf.random.truncated_normal(
                    [self._attention_hops, self._attention_depth],
                    stddev=0.1),
                name="WS2")

            rnn_layers_fw = [tf.nn.rnn_cell.GRUCell(size) for size in (
                [self._rnn_state_size] * self._rnn_depth)]
            rnn_layers_bw = [tf.nn.rnn_cell.GRUCell(size) for size in (
                [self._rnn_state_size] * self._rnn_depth)]

            self.cell_fw = tf.nn.rnn_cell.MultiRNNCell(rnn_layers_fw)
            self.cell_bw = tf.nn.rnn_cell.MultiRNNCell(rnn_layers_bw)

        # WARNING: possible error!
        # Shouldn't the two function_* share the weights?
        with tf.name_scope('Self-Attentive1'):
            self.function_1 = self._self_attentive_network(
                self.placeholders['x_1'],
                self.placeholders['lengths_1'])

        with tf.name_scope('Self-Attentive2'):
            self.function_2 = self._self_attentive_network(
                self.placeholders['x_2'],
                self.placeholders['lengths_2'])

        self.dense_1 = tf.nn.relu(tf.layers.dense(
            self.function_1, self._dense_layer_size))
        self.dense_2 = tf.nn.relu(tf.layers.dense(
            self.function_2, self._dense_layer_size))

        with tf.name_scope('Embedding1'):
            function_embedding_1 = tf.layers.dense(
                self.dense_1, self._embedding_size)

        with tf.name_scope('Embedding2'):
            function_embedding_2 = tf.layers.dense(
                self.dense_2, self._embedding_size)

        with tf.name_scope('siamese_layer'):
            cos_similarity = tf.reduce_sum(
                tf.multiply(function_embedding_1,
                            function_embedding_2),
                axis=1,
                name="cosSimilarity")

            pair_auc = auc(
                cos_similarity,
                self.placeholders['labels'])

        # CalculateMean cross-entropy loss
        with tf.name_scope("Loss"):
            A_square = tf.matmul(self.A, tf.transpose(self.A, perm=[0, 2, 1]))
            I_mat = tf.eye(tf.shape(A_square)[1])
            I_tiled = tf.tile(tf.expand_dims(I_mat, 0),
                              [tf.shape(A_square)[0], 1, 1],
                              name="I_tiled")
            self.A_pen = tf.norm(A_square - I_tiled)

            loss = tf.reduce_sum(
                tf.math.squared_difference(
                    cos_similarity,
                    self.placeholders['labels']),
                name="loss")
            regularized_loss = loss + \
                self._l2_reg_lambda * l2_loss + self.A_pen

        # Train step
        with tf.name_scope("Train_Step"):
            train_step = tf.compat.v1.train.AdamOptimizer(
                self._learning_rate).minimize(regularized_loss,
                                              global_step=self.global_step)

        # Output tensors
        self.tensors = {
            'train_step': train_step,
            'metrics': {
                'training': {
                    'loss': loss,
                    'regularized_loss': regularized_loss,
                    'norms': norms
                },
                'evaluation': {
                    'pair_similarity': cos_similarity,
                    'pair_labels': self.placeholders['labels'],
                    'pair_auc': pair_auc
                },
            },
            'embeddings': {
                'embedding_1': function_embedding_1,
                'embedding_2': function_embedding_2
            }
        }
        return
