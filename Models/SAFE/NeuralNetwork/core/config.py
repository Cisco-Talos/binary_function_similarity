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

import json
import os

import logging
log = logging.getLogger('safe')


def dump_config_to_json(config, outputdir):
    """
    Dump the configuration file to JSON

    Args
        config: a dictionary with model configuration
        outputdir: path of the output directory
    """
    with open(os.path.join(outputdir, "config.json"), "w") as f_out:
        json.dump(config, f_out)
    return


def update_config_datasetone(config_dict, outputdir, featuresdir):
    """Config for Dataset-1."""
    inputdir = "/input/Dataset-1/"

    # Training
    config_dict['training']['df_train_path'] = \
        os.path.join(inputdir, "training_Dataset-1.csv")
    config_dict['training']['features_train_path'] = \
        os.path.join(
            featuresdir, "Dataset-1_training",
            "instructions_embeddings_list_250.json")

    # Validation
    valdir = os.path.join(inputdir, "pairs", "validation")
    config_dict['validation'] = dict(
        positive_path=os.path.join(valdir, "pos_validation_Dataset-1.csv"),
        negative_path=os.path.join(valdir, "neg_validation_Dataset-1.csv"),
        features_validation_path=os.path.join(
            featuresdir,
            "Dataset-1_validation",
            "instructions_embeddings_list_250.json")
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
            "instructions_embeddings_list_250.json")
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
            "instructions_embeddings_list_250.json")
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
            "instructions_embeddings_list_250.json")
    )


def get_config(args):
    """The default configs."""

    config_dict = dict(
        # Dimension of each function embedding
        embedding_size=100,
        random_embeddings=args.random_embeddings,
        trainable_embeddings=args.trainable_embeddings,
        path_embedding_matrix=args.embedding_matrix,
        max_instructions=args.max_instructions,

        rnn_depth=1,
        rnn_state_size=50,
        dense_layer_size=2000,
        attention_hops=10,
        attention_depth=250,

        training=dict(
            learning_rate=0.001,
            l2_reg_lambda=0,
            num_epochs=args.num_epochs,
            print_after=100
        ),
        validation=dict(),
        testing=dict(),

        # -1: whole dataset
        batch_size=250,
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
