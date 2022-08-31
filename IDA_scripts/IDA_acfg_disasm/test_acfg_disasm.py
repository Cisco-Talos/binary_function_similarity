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
#  test_acfg_disasm.py                                                       #
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

    def test_acfg_disasm(self):
        selected = 'testdata/selected_hello.json'
        gt_json = 'testdata/hello_acfg_disasm.json'
        output_dir = 'testdata/acfg_disasm_jsons'
        output_json = 'hello_acfg_disasm.json'

        runner = CliRunner()
        result = runner.invoke(main, ['-j', selected, '-o', output_dir])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.isdir(output_dir))
        self.assertTrue(os.path.isfile(os.path.join(output_dir, output_json)))

        with open(gt_json) as f:
            j_gt = json.load(f)
            self.remove_elaspesed_time(j_gt)
        with open(os.path.join(output_dir, output_json)) as f:
            j_o = json.load(f)
            self.remove_elaspesed_time(j_o)
        self.assertDictEqual(j_gt, j_o)

        # Cleanup files
        self.addCleanup(os.remove, 'acfg_disasm_log.txt')
        self.addCleanup(shutil.rmtree, output_dir)
