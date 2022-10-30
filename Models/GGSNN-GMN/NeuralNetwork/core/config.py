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

import json
import os

import logging
log = logging.getLogger('gnn')


def dump_config_to_json(config, outputdir):
    """
    Dump the configuration file to JSON

    Args:
        config: a dictionary with model configuration
        outputdir: path of the output directory
    """
    with open(os.path.join(outputdir, "config.json"), "w") as f_out:
        json.dump(config, f_out)
    return


def get_use_features(features_type):
    """Do not use features if the option is selected."""
    if features_type == "nofeatures":
        return False
    return True


def get_bb_features_size(features_type):
    """Return features size by type."""
    if features_type == "nofeatures":
        return 7
    if features_type == "opc":
        return 200
    raise ValueError("Invalid features_type")


def update_config_datasetone(config_dict, outputdir, featuresdir):
    """Config for Dataset-1."""
    inputdir = "/input/Dataset-1/"

    # Training
    config_dict['training']['df_train_path'] = \
        os.path.join(inputdir, "training_Dataset-1.csv")
    config_dict['training']['features_train_path'] = \
        os.path.join(
            featuresdir, "Dataset-1_training",
            "graph_func_dict_opc_200.json")

    # Validation
    valdir = os.path.join(inputdir, "pairs", "validation")
    config_dict['validation'] = dict(
        positive_path=os.path.join(valdir, "pos_validation_Dataset-1.csv"),
        negative_path=os.path.join(valdir, "neg_validation_Dataset-1.csv"),
        features_validation_path=os.path.join(
            featuresdir,
            "Dataset-1_validation",
            "graph_func_dict_opc_200.json")
    )

    # Testing
    testdir = os.path.join(inputdir, "pairs", "testing")
    config_dict['testing'] = dict(
        full_tests_inputs=[
            os.path.join(testdir, "neg_rank_testing_Dataset-1.csv"),
            os.path.join(testdir, "neg_testing_Dataset-1.csv"),
            os.path.join(testdir, "pos_rank_testing_Dataset-1.csv"),
            os.path.join(testdir, "pos_testing_Dataset-1.csv")
        ],
        full_tests_outputs=[
            os.path.join(outputdir, "neg_rank_testing_Dataset-1_sim.csv"),
            os.path.join(outputdir, "neg_testing_Dataset-1_sim.csv"),
            os.path.join(outputdir, "pos_rank_testing_Dataset-1_sim.csv"),
            os.path.join(outputdir, "pos_testing_Dataset-_sim2.csv")
        ],
        features_testing_path=os.path.join(
            featuresdir,
            "Dataset-1_testing",
            "graph_func_dict_opc_200.json")
    )


def update_config_datasettwo(config_dict, outputdir, featuresdir):
    """Config for Dataset-2."""
    testdir = "/input/Dataset-2/pairs"
    config_dict['testing'] = dict(
        full_tests_inputs=[
            os.path.join(testdir, "neg_rank_testing_Dataset-2.csv"),
            os.path.join(testdir, "neg_testing_Dataset-2.csv"),
            os.path.join(testdir, "pos_rank_testing_Dataset-2.csv"),
            os.path.join(testdir, "pos_testing_Dataset-2.csv")
        ],
        full_tests_outputs=[
            os.path.join(outputdir, "neg_rank_testing_Dataset-2_sim.csv"),
            os.path.join(outputdir, "neg_testing_Dataset-2_sim.csv"),
            os.path.join(outputdir, "pos_rank_testing_Dataset-2_sim.csv"),
            os.path.join(outputdir, "pos_testing_Dataset-_sim2.csv")
        ],
        features_testing_path=os.path.join(
            featuresdir,
            "Dataset-2",
            "graph_func_dict_opc_200.json")
    )


def update_config_datasetvuln(config_dict, outputdir, featuresdir):
    """Config for Dataset-Vulnerability."""
    testdir = "/input/Dataset-Vulnerability/pairs"
    config_dict['testing'] = dict(
        full_tests_inputs=[
            os.path.join(testdir, "pairs_testing_Dataset-Vulnerability.csv")
        ],
        full_tests_outputs=[
            os.path.join(outputdir, "pairs_testing_Dataset-Vulnerability.csv")
        ],
        features_testing_path=os.path.join(
            featuresdir,
            "Dataset-Vulnerability",
            "graph_func_dict_opc_200.json")
    )


def get_config(args):
    """The default configs."""
    NODE_STATE_DIM = 32
    GRAPH_REP_DIM = 128

    graph_embedding_net_config = dict(
        node_state_dim=NODE_STATE_DIM,
        edge_hidden_sizes=[NODE_STATE_DIM * 2, NODE_STATE_DIM * 2],
        node_hidden_sizes=[NODE_STATE_DIM * 2],
        n_prop_layers=5,
        # set to False to not share parameters across message passing layers
        share_prop_params=True,
        # initialize message MLP with small parameter weights to prevent
        # aggregated message vectors blowing up, alternatively we could use
        # e.g. layer normalization to keep the scale of these under control.
        edge_net_init_scale=0.1,
        # other types of update like `mlp` and `residual` can also be used
        # here.
        node_update_type='gru',
        # set to False if your graph already contains edges in both directions.
        use_reverse_direction=True,
        # *FS option
        # set to True if your graph is directed
        reverse_dir_param_different=True,
        # we didn't use layer norm in our experiments but sometimes this can
        # help.
        layer_norm=False)

    graph_matching_net_config = graph_embedding_net_config.copy()

    # Alternatives are 'euclidean', 'dotproduct', 'cosine'
    graph_matching_net_config['similarity'] = 'dotproduct'

    config_dict = dict(
        encoder=dict(
            node_hidden_sizes=[NODE_STATE_DIM],
            edge_hidden_sizes=None),

        aggregator=dict(
            node_hidden_sizes=[GRAPH_REP_DIM],
            graph_transform_sizes=[GRAPH_REP_DIM],
            gated=True,
            aggregation_type='sum'),

        graph_embedding_net=graph_embedding_net_config,
        graph_matching_net=graph_matching_net_config,

        model_type=args.model_type,
        max_vertices=-1,
        edge_feature_dim=1,

        features_type=args.features_type,
        bb_features_size=get_bb_features_size(args.features_type),
        data=dict(
            use_features=get_use_features(args.features_type)),

        training=dict(
            mode=args.training_mode,
            # Alternative is 'hamming' ('margin' == -euclidean)
            loss='margin',
            margin=1.0,
            # A small regularizer on the graph vector scales to avoid the graph
            # vectors blowing up.  If numerical issues is particularly bad in
            # the model we can add `snt.LayerNorm` to the outputs of each layer
            # , the aggregated messages and aggregated node representations to
            # keep the network activation scale in a reasonable range.
            graph_vec_regularizer_weight=1e-6,
            # Add gradient clipping to avoid large gradients.
            clip_value=10.0,
            learning_rate=1e-3,
            num_epochs=args.num_epochs,
            print_after=100),
        validation=dict(),
        testing=dict(),

        batch_size=20,
        checkpoint_dir=args.checkpointdir,
        seed=11
    )
    if args.dataset == 'one':
        update_config_datasetone(
            config_dict, args.outputdir, args.featuresdir)
    elif args.dataset == 'two':
        update_config_datasettwo(
            config_dict, args.outputdir, args.featuresdir)
    elif args.dataset == 'vuln':
        update_config_datasetvuln(
            config_dict, args.outputdir, args.featuresdir)

    return config_dict
