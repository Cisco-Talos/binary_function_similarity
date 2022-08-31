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
#  test_large_flowchart.py                                                   #
#                                                                            #
##############################################################################

import os
import unittest

from cli_flowchart import main
from click.testing import CliRunner
from pandas import merge
from pandas import read_csv
from pandas.testing import assert_frame_equal


class TestIDAFlowchart(unittest.TestCase):

    def test_flowchart(self):
        idbs_dir = "testdata_large/IDBs"
        output_csv = "testdata_large/output_flowchart.csv"
        gt_csv = "testdata_large/gt/test_flowchart.csv"

        runner = CliRunner()
        result = runner.invoke(main, ['-i', idbs_dir, '-o', output_csv])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.exists(output_csv))

        df_output = read_csv(output_csv)

        df_gt = read_csv(gt_csv)
        df_gt.sort_values(['idb_path', 'fva'], inplace=True)
        df_gt.reset_index(drop=True, inplace=True)

        # find the intersection between the two
        df_join = merge(
            df_output,
            df_gt,
            on=['idb_path', 'fva'],
            how="right",
            suffixes=('', '_y')).filter(regex='^(?!.*_y)')
        df_join.sort_values(['idb_path', 'fva'], inplace=True)
        df_join.reset_index(drop=True, inplace=True)

        # then compare over the intersection only
        assert_frame_equal(df_join, df_gt)

        # Cleanup files
        self.addCleanup(os.remove, output_csv)
        self.addCleanup(os.remove, 'flowchart_log.txt')
