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

import numpy as np
import tensorflow as tf

from .build_dataset import fill_feed_dict
from sklearn import metrics

import logging
log = logging.getLogger('zeek')


def auc(scores, labels, **auc_args):
    """Compute the AUC for pair classification.

    See `tf.metrics.auc` for more details about this metric.

    Args
      scores: [n_examples] float.  Higher scores mean higher preference
        of being assigned the label of +1.
      labels: [n_examples] int.  Labels are either +1 or -1.
      **auc_Args other arguments that can be used by `tf.metrics.auc`.

    Returns
      auc: the area under the ROC curve.
    """
    # The following code should be used according to the tensorflow official
    # documentation:
    # value, _ = tf.metrics.auc(labels, scores, **auc_args)

    # However `tf.metrics.auc` is currently (as of July 23, 2019)
    # buggy so we have to use the following:
    _, value = tf.compat.v1.metrics.auc(labels, scores, **auc_args)
    return value


def evaluate(sess, eval_metrics, placeholders, batch_generator):
    """Evaluate model performance on the dataset corresponding to
        the batch_generator.

    Args
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing the tensors to evaluate, like
        'pair_auc' and 'triplet_acc'
      placeholders: a placeholder dict.
      batch_generator: a `PairFactory` instance, calling `pairs`
        functions with `batch_size` creates iterators over
        a finite sequence of batches to evaluate on.

    Returns
      metrics: a dict of metric name => value mapping.
    """
    # Not available in this model
    # accumulated_triplet_acc = []

    # It holds the avg of auc for each batch
    accumulated_pair_auc = list()

    # It holds the list of AUC over each db type
    pair_auc_dbtype_list = list()

    # They hold the similarity and label for each graph in input
    pair_similarity_list = list()
    pair_label_list = list()

    for batch in batch_generator.pairs():
        feed_dict = fill_feed_dict(placeholders, batch)
        pair_auc, pair_similarity, pair_labels = sess.run(
            [
                eval_metrics['pair_auc'],
                eval_metrics['pair_similarity'],
                eval_metrics['pair_labels']],
            feed_dict=feed_dict)

        accumulated_pair_auc.append(pair_auc)
        pair_similarity_list.extend(pair_similarity)
        pair_label_list.extend(pair_labels)

    pair_similarity_list = np.array(pair_similarity_list)
    pair_label_list = np.array(pair_label_list)

    # Iterate over each test_case in the testing db
    for item in batch_generator.get_indexes_by_db_type():
        # Name of the test case
        test_db_type = item[0]
        # List of indexes for this test case
        indexes = list(item[1])

        l_fpr, l_tpr, l_thresholds = metrics.roc_curve(
            # select the labels at "indexes"
            pair_label_list[indexes],
            # select the similarity output at "indexes"
            pair_similarity_list[indexes],
            # net_label = 0
            pos_label=1)
        l_auc = metrics.auc(l_fpr, l_tpr)

        # Add the AUC for the test case
        pair_auc_dbtype_list.append((
            test_db_type,
            l_auc
        ))

    return {
        # Pair_AUC is the AVG AUC over all the batches
        'avg_pair_auc': np.mean(accumulated_pair_auc),
        # This is the AUC for each test case separately
        'pair_auc_dbtype_list': pair_auc_dbtype_list
    }


def evaluate_sim(sess, eval_metrics, placeholders, batch_generator):
    """Evaluate the similarity on the dataset corresponding to
        the batch_generator.

     Args
      sess: a `tf.Session` instance used to run the computation.
      eval_metrics: a dict containing the tensors to evaluate,
        'pair_similarity'
      placeholders: a placeholder dict.
      batch_generator: a `PairFactory` instance, calling `pairs`
        functions with `batch_size` creates iterators over a
        finite sequence of batches to evaluate on.

    Returns
      A numpy array with the list of cosine similarities for the
        dataset in input.
    """
    similarity_list = list()

    for batch in batch_generator.pairs():
        feed_dict = fill_feed_dict(placeholders, batch)
        similarity, = sess.run(
            [eval_metrics['pair_similarity']],
            feed_dict=feed_dict)
        similarity_list.extend(similarity)

    # Return the similarity for all the pairs in input
    return np.array(similarity_list)
