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
#  test_large_fss.py                                                         #
#                                                                            #
##############################################################################

import json
import os
import shutil
import unittest

from cli_fss import main
from click.testing import CliRunner


class TestIDAFss(unittest.TestCase):

    def test_fss(self):
        selected = 'testdata_large/selected_functions.json'
        output_dir = 'testdata_large/fss_jsons'
        gt_dir = 'testdata_large/gt'

        runner = CliRunner()
        result = runner.invoke(main, ['-j', selected, '-o', output_dir, '-c'])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.isdir(output_dir))

        gt_json_files = [j for j in os.listdir(gt_dir) if j.endswith(".json")]
        out_json_files = [j for j in os.listdir(
            output_dir) if j.endswith(".json")]

        # check that the file names are the same
        self.assertListEqual(sorted(gt_json_files), sorted(out_json_files))

        for file_name in gt_json_files:
            with open(os.path.join(gt_dir, file_name)) as f:
                j_gt = json.load(f)
            with open(os.path.join(output_dir, file_name)) as f:
                j_o = json.load(f)
            self.assertDictEqual(j_gt, j_o)

        # Cleanup files
        self.addCleanup(os.remove, 'fss_log.txt')
        self.addCleanup(shutil.rmtree, output_dir)
