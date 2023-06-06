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

import tensorflow as tf

from .model_evaluation import auc
from .model_evaluation import compute_similarity
from .graph_aggregator import GraphAggregator
from .graph_embedding_net import GraphEmbeddingNet
from .graph_encoder import GraphEncoder
from .graph_matching_network import GraphMatchingNet
from .loss import pairwise_loss
from .loss import triplet_loss

import logging
log = logging.getLogger('gnn')


def build_matchings(layer_outputs, graph_idx, n_graphs, sim):
    """Build the matching attention matrices from layer outputs.

    Args:
      layer_outputs:
      graph_idx:
      n_graphs:
      sim:
    """
    assert n_graphs % 2 == 0
    attention = []
    for h in layer_outputs:
        partitions = tf.dynamic_partition(h, graph_idx, n_graphs)
        attention_in_layer = []
        for i in range(0, n_graphs, 2):
            x = partitions[i]
            y = partitions[i + 1]
            a = sim(x, y)
            a_x = tf.nn.softmax(a, axis=1)  # i->j
            a_y = tf.nn.softmax(a, axis=0)  # j->i
            attention_in_layer.append((a_x, a_y))
        attention.append(attention_in_layer)
    return attention


def reshape_and_split_tensor(tensor, n_splits):
    """Reshape and split a 2D tensor along the last dimension.

    Args:
      tensor: a [num_examples, feature_dim] tensor.  num_examples must be a
        multiple of `n_splits`.
      n_splits: int, number of splits to split the tensor into.

    Returns:
      splits: a list of `n_splits` tensors.  The first split is [tensor[0],
        tensor[n_splits], tensor[n_splits * 2], ...], the second split is
        [tensor[1], tensor[n_splits + 1], tensor[n_splits * 2 + 1], ...], etc..
    """
    feature_dim = tensor.shape.as_list()[-1]
    # feature dim must be known, otherwise you can provide that as an input
    assert isinstance(feature_dim, int)
    tensor = tf.reshape(tensor, [-1, feature_dim * n_splits])
    return tf.split(tensor, n_splits, axis=-1)


def build_placeholders(node_feature_dim, edge_feature_dim):
    """Build the placeholders needed for the model.

    Args:
      node_feature_dim: int.
      edge_feature_dim: int.

    Returns:
      placeholders: a placeholder name -> placeholder tensor dict.
    """
    return {
        'node_features': tf.compat.v1.placeholder(
            tf.float32, [None, node_feature_dim]),

        'edge_features': tf.compat.v1.placeholder(
            tf.float32, [None, edge_feature_dim]),

        'from_idx': tf.compat.v1.placeholder(
            tf.int32, [None]),

        'to_idx': tf.compat.v1.placeholder(
            tf.int32, [None]),

        'graph_idx': tf.compat.v1.placeholder(
            tf.int32, [None]),

        # only used for pairwise training and evaluation
        'labels': tf.compat.v1.placeholder(
            tf.int32, [None]),
    }


def build_model(config, node_feature_dim, edge_feature_dim):
    """Create model for training and evaluation.

    Args:
      config: a dictionary of configs, like the one created by the
        `get_default_config` function.
      node_feature_dim: int, dimensionality of node features.
      edge_feature_dim: int, dimensionality of edge features.

    Returns:
      tensors: a (potentially nested) name => tensor dict.
      placeholders: a (potentially nested) name => tensor dict.
      model: a GraphEmbeddingNet or GraphMatchingNet instance.

    Raises:
      ValueError: if the specified model or training settings
      are not supported.
    """
    encoder = GraphEncoder(**config['encoder'])
    aggregator = GraphAggregator(**config['aggregator'])

    if config['model_type'] == 'embedding':
        log.info("Building embedding model")
        model = GraphEmbeddingNet(
            encoder, aggregator,
            **config['graph_embedding_net'])

    elif config['model_type'] == 'matching':
        log.info("Building matching model")
        model = GraphMatchingNet(
            encoder, aggregator,
            **config['graph_matching_net'])
    else:
        raise ValueError('Unknown model type: {}'.format(config['model_type']))

    if config['training']['mode'] == 'pair':
        graphs_per_batch = config['batch_size'] * 2
    elif config['training']['mode'] == 'triplet':
        graphs_per_batch = config['batch_size'] * 4
    else:
        raise ValueError('Unknown training mode: {}'.format(
            config['training']['mode']))

    placeholders = build_placeholders(node_feature_dim, edge_feature_dim)

    # training
    model_inputs = placeholders.copy()
    del model_inputs['labels']
    model_inputs['n_graphs'] = graphs_per_batch
    graph_vectors = model(**model_inputs)

    if config['training']['mode'] == 'pair':
        x, y = reshape_and_split_tensor(graph_vectors, 2)
        loss = pairwise_loss(x, y, placeholders['labels'],
                             loss_type=config['training']['loss'],
                             margin=config['training']['margin'])

        # optionally monitor the similarity between positive and negative pairs
        is_pos = tf.cast(tf.equal(placeholders['labels'], 1), tf.float32)
        is_neg = 1 - is_pos
        n_pos = tf.reduce_sum(is_pos)
        n_neg = tf.reduce_sum(is_neg)
        sim = compute_similarity(config, x, y)
        sim_pos = tf.reduce_sum(sim * is_pos) / (n_pos + 1e-8)
        sim_neg = tf.reduce_sum(sim * is_neg) / (n_neg + 1e-8)
    else:
        x_1, y, x_2, z = reshape_and_split_tensor(graph_vectors, 4)
        loss = triplet_loss(x_1, y, x_2, z,
                            loss_type=config['training']['loss'],
                            margin=config['training']['margin'])

        sim_pos = tf.reduce_mean(compute_similarity(config, x_1, y))
        sim_neg = tf.reduce_mean(compute_similarity(config, x_2, z))

    graph_vec_scale = tf.reduce_mean(graph_vectors**2)
    if config['training']['graph_vec_regularizer_weight'] > 0:
        grw = config['training']['graph_vec_regularizer_weight']
        loss += (grw * 0.5 * graph_vec_scale)

    # monitor scale of the parameters and gradients, these are typically
    # helpful
    optimizer = tf.compat.v1.train.AdamOptimizer(
        learning_rate=config['training']['learning_rate'])
    grads_and_params = optimizer.compute_gradients(loss)
    grads, params = zip(*grads_and_params)
    grads, _ = tf.clip_by_global_norm(grads, config['training']['clip_value'])
    train_step = optimizer.apply_gradients(zip(grads, params))

    grad_scale = tf.global_norm(grads)
    param_scale = tf.global_norm(params)

    # evaluation
    model_inputs['n_graphs'] = config['batch_size'] * 2
    eval_pairs = model(**model_inputs)
    x, y = reshape_and_split_tensor(eval_pairs, 2)
    similarity = compute_similarity(config, x, y)
    pair_auc = auc(similarity, placeholders['labels'])

    model_inputs['n_graphs'] = config['batch_size'] * 4
    eval_triplets = model(**model_inputs)
    x_1, y, x_2, z = reshape_and_split_tensor(eval_triplets, 4)
    sim_1 = compute_similarity(config, x_1, y)
    sim_2 = compute_similarity(config, x_2, z)
    triplet_acc = tf.reduce_mean(tf.cast(sim_1 > sim_2, dtype=tf.float32))

    return {
        'train_step': train_step,
        'metrics': {
            'training': {
                'loss': loss,
                'grad_scale': grad_scale,
                'param_scale': param_scale,
                'graph_vec_scale': graph_vec_scale,
                'sim_pos': sim_pos,
                'sim_neg': sim_neg,
                'sim_diff': sim_pos - sim_neg,
            },
            'evaluation': {
                'pair_similarity': similarity,
                'pair_labels': placeholders['labels'],
                'pair_auc': pair_auc,
                'triplet_acc': triplet_acc,
            },
        },
    }, placeholders, model
