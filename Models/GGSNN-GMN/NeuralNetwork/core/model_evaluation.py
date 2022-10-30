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

import numpy as np
import tensorflow as tf

from .build_dataset import fill_feed_dict
from .similarities import euclidean_distance
from .similarities import exact_hamming_similarity
from sklearn import metrics

import logging
log = logging.getLogger('gnn')


def compute_similarity(config, x, y):
    """Compute the distance between x and y vectors.

    The distance will be computed based on the training loss type.

    Args:
      config: a config dict.
      x: [n_examples, feature_dim] float tensor.
      y: [n_examples, feature_dim] float tensor.

    Returns:
      dist: [n_examples] float tensor.

    Raises:
      ValueError: if loss type is not supported.
    """
    if config['training']['loss'] == 'margin':
        # similarity is negative distance
        return -euclidean_distance(x, y)
    elif config['training']['loss'] == 'hamming':
        return exact_hamming_similarity(x, y)
    else:
        raise ValueError('Unknown loss type %s' % config['training']['loss'])


def auc(scores, labels, **auc_args):
    """Compute the AUC for pair classification.

    See `tf.metrics.auc` for more details about this metric.

    Args:
      scores: [n_examples] float.  Higher scores mean higher preference
        of being assigned the label of +1.
      labels: [n_examples] int.  Labels are either +1 or -1.
      **auc_args other arguments that can be used by `tf.metrics.auc`.

    Returns:
      auc: the area under the ROC curve.
    """
    scores_max = tf.reduce_max(scores)
    scores_min = tf.reduce_min(scores)
    # normalize scores to [0, 1] and add a small epislon for safety
    scores = (scores - scores_min) / (scores_max - scores_min + 1e-8)

    labels = (labels + 1) / 2
    # The following code should be used according to the tensorflow official
    # documentation:
    # value, _ = tf.metrics.auc(labels, scores, **auc_args)

    # However `tf.metrics.auc` is currently (as of July 23, 2019)
    # buggy so we have to use the following:
    _, value = tf.compat.v1.metrics.auc(labels, scores, **auc_args)
    return value


def evaluate(sess, eval_metrics, placeholders, batch_generator):
    """Evaluate model performance on the given validation set.

    Args:
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing two tensors 'pair_auc' and 'triplet_acc'.
      placeholders: a placeholder dict.
      batch_generator: a `GraphFactoryBase` instance, calling `pairs` and
        `triplets` functions with `batch_size` creates iterators over a finite
        sequence of batches to evaluate on.

    Returns:
      metrics: a dict of metric name => value mapping.
    """
    accumulated_pair_auc = []
    similarity_list = list()
    label_list = list()

    for batch in batch_generator.pairs():

        feed_dict = fill_feed_dict(placeholders, batch)

        similarity, labels, pair_auc = sess.run(
            [eval_metrics['pair_similarity'],
             eval_metrics['pair_labels'],
             eval_metrics['pair_auc']],
            feed_dict=feed_dict)

        accumulated_pair_auc.append(pair_auc)
        similarity_list.extend(similarity)
        label_list.extend(labels)

    similarity_list = np.array(similarity_list)
    label_list = np.array(label_list)

    pair_auc_list = list()
    for item in batch_generator.get_indexes_by_db_type():
        db_type = item[0]
        indexes = list(item[1])

        l_fpr, l_tpr, l_thresholds = metrics.roc_curve(
            label_list[indexes], similarity_list[indexes], pos_label=1)
        l_auc = metrics.auc(l_fpr, l_tpr)

        pair_auc_list.append((
            db_type,
            l_auc
        ))

    accumulated_triplet_acc = []
    # for batch in batch_generator.triplets():
    #     feed_dict = fill_feed_dict(placeholders, batch)
    #     triplet_acc = sess.run(
    #         eval_metrics['triplet_acc'], feed_dict=feed_dict)
    #     accumulated_triplet_acc.append(triplet_acc)

    return {
        'pair_auc': np.mean(accumulated_pair_auc),
        'pair_auc_list': pair_auc_list,
        'triplet_acc': np.mean(accumulated_triplet_acc),
    }


def evaluate_sim(sess, eval_metrics, placeholders, batch_generator):
    """Compute the similarity among the batch_generator pairs.

    Args:
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing two tensors 'pair_auc' and 'triplet_acc'.
      placeholders: a placeholder dict.
      batch_generator: a `GraphFactoryBase` instance, calling `pairs` and
        `triplets` functions with `batch_size` creates iterators over a finite
        sequence of batches to evaluate on.

    Returns:
      metrics: a dict of metric name => value mapping.
    """
    similarity_list = list()

    for batch in batch_generator.pairs():

        feed_dict = fill_feed_dict(placeholders, batch)
        similarity, = sess.run(
            [eval_metrics['pair_similarity']],
            feed_dict=feed_dict)
        similarity_list.extend(similarity)

    return np.array(similarity_list)
