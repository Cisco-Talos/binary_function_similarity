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
##############################################################################

import numpy as np
import tensorflow as tf

from .build_dataset import fill_feed_dict
from sklearn import metrics

import logging

log = logging.getLogger("s2v")


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


def evaluate(sess, eval_metrics, placeholders, batch_generator, network_type):
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
        feed_dict = fill_feed_dict(placeholders, batch, network_type)
        pair_auc, pair_similarity, pair_labels = sess.run(
            [
                eval_metrics["pair_auc"],
                eval_metrics["pair_similarity"],
                eval_metrics["pair_labels"],
            ],
            feed_dict=feed_dict,
        )

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
            pair_labels_list[test_idx], pair_similarity_list[test_idx], pos_label=1
        )
        l_auc = metrics.auc(l_fpr, l_tpr)

        pair_auc_dbtype_list.append((test_name, l_auc))

    return {
        # The avg AUC over all the batches
        "avg_pair_auc": np.mean(pair_auc_list),
        # The AUC for each test case separately
        "pair_auc_dbtype_list": pair_auc_dbtype_list,
    }


def evaluate_sim(sess, eval_metrics, placeholders, batch_generator, network_type):
    """Compute the similarity among the batch_generator pairs.

     Args
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing the tensors to evaluate
      placeholders: a placeholder dict
      batch_generator: a `PairFactory` instance, calling `pairs`
        functions with `batch_size` creates iterators over a
        finite sequence of batches to evaluate on
      network_type: type of NN

    Returns
      A Numpy array with the cosine similarities for the input pairs.
    """
    pair_similarity_list = list()

    for batch in batch_generator.pairs():
        feed_dict = fill_feed_dict(placeholders, batch, network_type)
        (similarity,) = sess.run([eval_metrics["pair_similarity"]], feed_dict=feed_dict)
        pair_similarity_list.extend(similarity)

    return np.array(pair_similarity_list)
