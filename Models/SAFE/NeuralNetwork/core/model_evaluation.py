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

import numpy as np
import tensorflow as tf

from .build_dataset import fill_feed_dict
from sklearn import metrics

import logging
log = logging.getLogger('safe')


def auc(scores, labels, **auc_args):
    """Compute the AUC for pair classification.

    Args
      scores: [n_examples] float.  Higher scores mean higher preference
        of being assigned the label of +1.
      labels: [n_examples] int.  Labels are either +1 or -1.

    Returns
      float: the area under the ROC curve.
    """
    scores_max = tf.reduce_max(scores)
    scores_min = tf.reduce_min(scores)

    # normalize scores to [0, 1] and add a small epislon for safety
    scores = (scores - scores_min) / (scores_max - scores_min + 1e-8)
    labels = (labels + 1) / 2
    # WARNING: `tf.metrics.auc` is buggy (as of July 23, 2019)
    # value, _ = tf.metrics.auc(labels, scores, **auc_args)
    _, auc_value = tf.compat.v1.metrics.auc(labels, scores, **auc_args)
    return auc_value


def evaluate(sess, eval_metrics, placeholders, batch_generator):
    """Evaluate model performance on the dataset corresponding to
        the batch_generator.

    Args
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing the tensors to evaluate
      placeholders: a placeholder dict
      batch_generator: a `PairFactory` instance, calling `pairs`
        functions with `batch_size` creates iterators over a
        finite sequence of batches to evaluate on.

    Returns
      metrics: a dict of "metric name: value" mapping.
    """
    pair_auc_list = list()
    pair_auc_dbtype_list = list()
    pair_similarity_list = list()
    pair_labels_list = list()

    for batch in batch_generator.pairs():
        feed_dict = fill_feed_dict(placeholders, batch)
        pair_auc, pair_similarity, pair_labels = sess.run(
            [
                eval_metrics['pair_auc'],
                eval_metrics['pair_similarity'],
                eval_metrics['pair_labels']],
            feed_dict=feed_dict)
        pair_auc_list.append(pair_auc)
        pair_labels_list.extend(pair_labels)
        pair_similarity_list.extend(pair_similarity)

    pair_labels_list = np.array(pair_labels_list)
    pair_similarity_list = np.array(pair_similarity_list)

    # Compute the AUC for each test case
    for item in batch_generator.get_indexes_by_db_type():
        test_name = item[0]
        test_idx = list(item[1])
        l_fpr, l_tpr, l_thresholds = metrics.roc_curve(
            pair_labels_list[test_idx],
            pair_similarity_list[test_idx],
            pos_label=1)
        l_auc = metrics.auc(l_fpr, l_tpr)
        pair_auc_dbtype_list.append((test_name, l_auc))

    return {
        # The avg AUC over all the batches
        'avg_pair_auc': np.mean(pair_auc_list),

        # The AUC for each test case separately
        'pair_auc_dbtype_list': pair_auc_dbtype_list
    }


def evaluate_sim(sess, eval_metrics, placeholders, batch_generator):
    """Compute the similarity among the batch_generator pairs.

    Args
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing the tensors to evaluate
      placeholders: a placeholder dict
      batch_generator: a `PairFactory` instance, calling `pairs`
        functions with `batch_size` creates iterators over a
        finite sequence of batches to evaluate on.

    Returns
      A Numpy array with the cosine similarities for the input pairs.
    """
    pair_similarity_list = list()
    for batch in batch_generator.pairs():
        feed_dict = fill_feed_dict(placeholders, batch)
        similarity, = sess.run(
            [eval_metrics['pair_similarity']],
            feed_dict=feed_dict)
        pair_similarity_list.extend(similarity)
    return np.array(pair_similarity_list)
