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
#  test_large_catalog1.py                                                    #
#                                                                            #
##############################################################################

import os
import unittest

from cli_catalog1 import main
from click.testing import CliRunner
from pandas import read_csv
from pandas.testing import assert_frame_equal


class TestIDAcatalog1(unittest.TestCase):

    def test_catalog1(self):
        selected = 'testdata_large/selected_functions.json'
        output_csv = "testdata_large/output_catalog1.csv"
        gt_csv = "testdata_large/gt/test_catalog1.csv"

        # Cleanup old files
        for s in [16, 32, 64, 128]:
            output_csv_s = output_csv.replace(".csv", "_{}.csv".format(s))
            if os.path.isfile(output_csv_s):
                os.remove(output_csv_s)

        runner = CliRunner()
        result = runner.invoke(main, ['-j', selected, '-o', output_csv])
        self.assertEqual(result.exit_code, 0)

        for s in [16, 32, 64, 128]:
            output_csv_s = output_csv.replace(".csv", "_{}.csv".format(s))
            self.assertTrue(os.path.exists(output_csv_s))

            df_output = read_csv(output_csv_s)
            del df_output['time']
            df_output.sort_values(['path', 'address'], inplace=True)
            df_output.reset_index(drop=True, inplace=True)

            df_gt = read_csv(gt_csv.replace(".csv", "_{}.csv".format(s)))
            del df_gt['time']
            df_gt.sort_values(['path', 'address'], inplace=True)
            df_gt.reset_index(drop=True, inplace=True)

            assert_frame_equal(df_output, df_gt)

            # Cleanup files
            self.addCleanup(os.remove, output_csv_s)

        # Cleanup logs
        self.addCleanup(os.remove, 'catalog1_log.txt')
