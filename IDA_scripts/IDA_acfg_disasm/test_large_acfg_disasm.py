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
#  test_large_acfg_disasm.py                                                 #
#                                                                            #
##############################################################################

import json
import os
import shutil
import unittest

from cli_acfg_disasm import main
from click.testing import CliRunner


class TestIDAAcfgDisasm(unittest.TestCase):

    def remove_elaspesed_time(self, jd):
        """Elapsed time will be different in any run."""
        for idb, addr in jd.items():
            for va in addr:
                if isinstance(jd[idb][va], dict) \
                        and 'elapsed_time' in jd[idb][va]:
                    jd[idb][va]['elapsed_time'] = -1
        return jd

    def test_acfg_disasm_large(self):
        selected = 'testdata_large/selected_functions.json'
        gt_dir = 'testdata_large/gt'
        output_dir = 'testdata_large/acfg_disasm_jsons'

        runner = CliRunner()
        result = runner.invoke(main, ['-j', selected, '-o', output_dir])
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
                self.remove_elaspesed_time(j_gt)
            with open(os.path.join(output_dir, file_name)) as f:
                j_o = json.load(f)
                self.remove_elaspesed_time(j_o)
            self.assertDictEqual(j_gt, j_o)

        # Cleanup files
        self.addCleanup(os.remove, 'acfg_disasm_log.txt')
        self.addCleanup(shutil.rmtree, output_dir)
