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
#  test_codeCMR.py                                                           #
#                                                                            #
##############################################################################

import os
import pickle
import shutil
import unittest

from cli_codeCMR import main
from click.testing import CliRunner


class TestIDAcodeCMR(unittest.TestCase):

    def test_codeCMR(self):
        selected = 'testdata/selected_functions.json'
        output_dir = 'testdata/codeCMR_pickles'
        gt_dir = 'testdata/gt'

        runner = CliRunner()
        result = runner.invoke(main, ['-j', selected, '-o', output_dir])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.isdir(output_dir))

        gt_files = [p for p in os.listdir(gt_dir) if p.endswith(".pkl")]
        out_files = [p for p in os.listdir(output_dir) if p.endswith(".pkl")]

        # check that the file names are the same
        self.assertListEqual(sorted(gt_files), sorted(out_files))

        for f_name in gt_files:
            gt_path = os.path.join(gt_dir, f_name)
            pi_gt = pickle.load(open(gt_path, "rb"))
            func_list_gt = sorted(pi_gt.keys())

            out_path = os.path.join(output_dir, f_name)
            pi_out = pickle.load(open(out_path, "rb"))

            # Check that functions are the same
            self.assertListEqual(func_list_gt, sorted(pi_out.keys()))

            # Iterate over the functions
            for func in func_list_gt:
                g_out = pi_out[func]
                self.assertIsNotNone(g_out.graph.get('c_state'))
                self.assertIsNotNone(g_out.graph.get('c_int'))
                self.assertIsNotNone(g_out.graph.get('c_str'))
                self.assertIsNotNone(g_out.graph.get('m_int'))
                self.assertIsNotNone(g_out.graph.get('arg_num'))
                self.assertTrue(g_out.nodes)
                self.assertTrue(g_out.edges)
                for n in sorted(g_out.nodes):
                    self.assertIsNotNone(g_out.nodes[n].get('feat'))

        # Cleanup files
        self.addCleanup(os.remove, 'codeCMR_log.txt')
        self.addCleanup(shutil.rmtree, output_dir)
