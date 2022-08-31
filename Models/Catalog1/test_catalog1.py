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
#  test_catalog1.py                                                          #
#                                                                            #
##############################################################################

import os
import unittest

from cli_catalog1 import main
from click.testing import CliRunner


class TestIDAcatalog1(unittest.TestCase):

    def test_catalog1(self):
        selected = 'testdata/selected_hello.json'
        output_csv = "testdata/output_catalog1.csv"
        gt_csv = "testdata/gt/test_catalog1.csv"

        runner = CliRunner()
        result = runner.invoke(main, ['-j', selected, '-o', output_csv])
        self.assertEqual(result.exit_code, 0)

        for s in [16, 32, 64, 128]:
            output_csv_s = output_csv.replace(".csv", "_{}.csv".format(s))
            self.assertTrue(os.path.exists(output_csv_s))
            with open(output_csv_s) as f:
                # Skip the first column with the path
                # Skip last column with elapsed time
                l_o = f.read().splitlines()[1].split(",")[:-1]
            with open(gt_csv.replace(".csv", "_{}.csv".format(s))) as f:
                # Skip the first column with the path
                # Skip last column with elapsed time
                l_gt = f.read().splitlines()[1].split(",")[:-1]
            self.assertListEqual(l_gt, l_o)
            # Cleanup files
            self.addCleanup(os.remove, output_csv_s)

        # Cleanup logs
        self.addCleanup(os.remove, 'catalog1_log.txt')
