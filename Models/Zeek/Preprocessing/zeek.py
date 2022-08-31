#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
#  zeek.py - Call IDA_fss.py IDA script.                                     #
#                                                                            #
##############################################################################

import archinfo
import base64
import click
import coloredlogs
import hashlib
import json
import logging
import multiprocessing
import os
import pyvex
import shutil
import signal
import time
import traceback

from collections import Counter
from collections import defaultdict
from multiprocessing import Pool
from os.path import abspath
from os.path import basename
from os.path import exists
from os.path import isdir
from os.path import isfile
from os.path import join
from pwn import asm
from pwn import context
from pwn import u16
from tqdm import tqdm

log = None
g_start_time = time.time()
g_config = {}
g_debug = False
g_verbose = False

REG_BASE = 0x100000


@click.group()
def cli():
    pass


@cli.command()
@click.argument('file_or_dir_path')
@click.argument('experiment_dir')
@click.option('--function', 'target_func_addr')
@click.option('--block', 'target_block_addr')
@click.option('-d', '--debug', is_flag=True)
@click.option('-v', '--verbose', is_flag=True)
@click.option('--log-functions', is_flag=True)
@click.option('--log-blocks', is_flag=True)
@click.option('--log-selection', is_flag=True)
@click.option('-f', '--force', is_flag=True, help='Re-analyze each input JSON.')
@click.option('--select-with-error', 'select_with_error', is_flag=True, help='Re-analyze a JSON only if there was an error')
@click.option('--select-with-timeout', 'select_with_timeout', is_flag=True, help='Re-analyze a JSON only if there was a timeout')
@click.option('--dry-run', is_flag=True)
@click.option('--stop', 'stop_after_vex_block', is_flag=True)
@click.option('--print-exc', 'print_exceptions', is_flag=True)
@click.option('--stop-exc', 'stop_after_exception', is_flag=True)
@click.option('--scan-mode', 'scan_mode', is_flag=True)
@click.option('--start-idx', 'start_idx', default=0)
@click.option('--vex-timeout', 'vex_timeout', default=2)
@click.option('--hash-timeout', 'hash_timeout', default=2)
@click.option('--block-timeout', 'block_timeout', default=60)
@click.option('-w', '--workers-num', default=1)
@click.option('--max-tasks', 'max_tasks_per_child', default=5)
def process(file_or_dir_path, experiment_dir, target_func_addr,
            target_block_addr, verbose, debug, log_functions, log_blocks,
            log_selection, force, select_with_error, select_with_timeout,
            dry_run, stop_after_vex_block, print_exceptions, stop_after_exception,
            scan_mode, start_idx, vex_timeout, hash_timeout, block_timeout,
            workers_num, max_tasks_per_child):

    global g_config
    global g_debug
    global g_verbose

    if target_block_addr is not None:
        assert target_func_addr is not None

    if target_func_addr is not None:
        if not isfile(file_or_dir_path):
            print(f'ERROR: --function and --block are supported only for analyzing single files, not dirs')
            return
        force = True
        dry_run = True
    if scan_mode:
        force = True
        dry_run = True
    if stop_after_exception:
        print_exceptions = True

    experiment_dir = abspath(experiment_dir)
    logs_dir = join(experiment_dir, 'logs')
    jsons_dir = join(experiment_dir, 'jsons')

    g_config['debug'] = debug
    g_config['verbose'] = verbose
    g_config['log_functions'] = log_functions
    g_config['log_blocks'] = log_blocks
    g_config['log_selection'] = log_selection
    g_config['force'] = force
    g_config['select_with_error'] = select_with_error
    g_config['select_with_timeout'] = select_with_timeout
    g_config['dry_run'] = dry_run
    g_config['stop_after_vex_block'] = stop_after_vex_block
    g_config['print_exceptions'] = print_exceptions
    g_config['stop_after_exception'] = stop_after_exception
    g_config['scan_mode'] = scan_mode
    g_config['target_func_addr'] = target_func_addr
    g_config['target_block_addr'] = target_block_addr
    g_config['start_idx'] = start_idx
    g_config['vex_timeout'] = vex_timeout
    g_config['hash_timeout'] = hash_timeout
    g_config['block_timeout'] = block_timeout
    g_config['only_known_ops'] = False
    g_config['workers_num'] = workers_num
    g_config['max_tasks_per_child'] = max_tasks_per_child
    g_config['experiment_dir'] = experiment_dir
    g_config['jsons_dir'] = jsons_dir
    g_config['logs_dir'] = logs_dir
    g_debug = debug
    g_verbose = verbose

    target_dirs = [experiment_dir, jsons_dir, logs_dir]
    for target_dir in target_dirs:
        if not isdir(target_dir):
            if exists(target_dir):
                print(f'ERROR: {taget_dir} exists, but it is not a directory')
                return 1
            else:
                os.makedirs(target_dir)

    set_logger(debug, logs_dir)

    if isfile(file_or_dir_path):
        j_paths = [file_or_dir_path]
    elif isdir(file_or_dir_path):
        j_paths = []
        for fn in sorted(os.listdir(file_or_dir_path)):
            if fn.endswith('.json'):
                j_path = abspath(join(file_or_dir_path, fn))
                j_paths.append(j_path)
    else:
        raise Exception('file or dir does not exist')

    log.info(f'[M] Found {len(j_paths)} file(s) to process')

    results = list()
    log.info(f'[M] Creating workers_num: {g_config["workers_num"]}')
    pool = Pool(processes=g_config['workers_num'],
                maxtasksperchild=g_config['max_tasks_per_child'])

    # Iterate over each JSON file (each JSON corresponds to an IDB)
    for j_idx, j_path in enumerate(j_paths):
        if j_idx < start_idx:
            continue
        if workers_num == 1:
            worker_func(j_path, j_idx, len(j_paths))
        else:
            res = pool.apply_async(worker_func, args=(
                j_path, j_idx, len(j_paths)))
            results.append(res)

    log.info("[M] Waiting processes to finish")

    # Close the pool
    pool.close()
    pool.join()

    # Wait for all the async tasks to finish
    for res in results:
        res.get()
    log.info("[M] All processes finished")

    output_json_path = join(experiment_dir, 'zeek.json')
    log.info(f"[M] Now collecting all results in one single JSON file: {output_json_path}")

    j_paths = []
    for fn in sorted(os.listdir(jsons_dir)):
        if fn.endswith('.json'):
            j_path = abspath(join(jsons_dir, fn))
            j_paths.append(j_path)

    log.info(f'[M] Processing {len(j_paths)} jsons')

    results = {}
    for j_path in tqdm(j_paths):
        with open(j_path) as f:
            j_data = json.load(f)
            for binary_name, info in j_data.items():
                results[binary_name] = {}
                results[binary_name]['elapsed_time'] = info['elapsed_time']
                results[binary_name]['hashes'] = {}
                for func_addr, shash in info['hashes'].items():
                    results[binary_name]['hashes'][func_addr] = {
                        'sh': shash,
                    }

    with open(output_json_path, 'w') as f:
        f.write(json.dumps(results, sort_keys=True,
                           indent=2, separators=(',', ': ')))

    log.info("[M] Done")


@cli.command()
@click.argument('input_json_path')
@click.argument('results_json_path')
def check_completeness(input_json_path, results_json_path):
    with open(input_json_path) as f:
        input_info = json.load(f)
    with open(results_json_path) as f:
        results_info = json.load(f)

    for binary_name, func_addrs in input_info.items():
        analysis_info = results_info.get(binary_name, None)
        if analysis_info is None:
            print(f'ERROR: could not find analysis for {binary_name}')
            continue
        for func_addr in func_addrs:
            func_addr_hex = hex(func_addr)
            if func_addr_hex not in analysis_info.keys():
                print(f'ERROR: could not find {func_addr} / {func_addr_hex} in the results')
                import IPython
                IPython.embed(colors='neutral')


@cli.command()
@click.argument('input_dir')
@click.argument('experiment_dir')
def stats(input_dir, experiment_dir):

    jsons_dir = join(experiment_dir, 'jsons')

    assert isdir(input_dir)
    assert isdir(jsons_dir)

    input_j_paths = []
    for fn in sorted(os.listdir(input_dir)):
        if fn.endswith('.json'):
            j_path = abspath(join(input_dir, fn))
            input_j_paths.append(j_path)

    output_j_paths = []
    for fn in sorted(os.listdir(jsons_dir)):
        if fn.endswith('.json'):
            j_path = abspath(join(jsons_dir, fn))
            output_j_paths.append(j_path)

    cnt = Counter()
    errorscnt = Counter()
    tot_elapsed_time = 0
    tot_processed_funcs = 0
    tot_elapsed_time_without_errors = 0
    tot_processed_funcs_without_errors = 0
    for j_idx, j_path in enumerate(output_j_paths):
        print(j_idx)
        with open(j_path) as f:
            j_data = json.load(f)

            with_error, with_timeout = False, False
            for binary_name, res in j_data.items():
                tot_elapsed_time += res['elapsed_time']
                tot_processed_funcs += len(res['hashes'])
                if len(res['errors']) == 0:
                    tot_elapsed_time_without_errors += res['elapsed_time']
                    tot_processed_funcs_without_errors += len(res['hashes'])
                for func_name, errors in res['errors'].items():
                    for error in errors:
                        errorscnt[error.split('@')[-1]] += 1
                        if error.find('timeout') >= 0 or error.find('release unlocked lock') >= 0:
                            with_timeout = True
                        else:
                            with_error = True

            if not with_error and not with_timeout:
                cnt['success'] += 1
            elif not with_error and with_timeout:
                cnt['success-with-timeout'] += 1
            else:
                cnt['with-error'] += 1

    print(f'Got {len(input_j_paths)} input jsons')
    print(f'Got {len(output_j_paths)} output jsons')
    print(f'Cnt: {cnt}')
    print(f'Errors: {errorscnt}')
    print(f'Tot elapsed time: {tot_elapsed_time}')
    print(f'Tot processed functions: {tot_processed_funcs}')
    print(f'Tot elapsed time without errors: {tot_elapsed_time_without_errors}')
    print(f'Tot processed functions without errors: {tot_processed_funcs_without_errors}')


@cli.command()
@click.argument('input_path')
def inputstats(input_path):
    """
    Compute stats on the input file specifying what to test, such as
    testing_functions.json.
    """
    assert isfile(input_path)

    tot_funcs = 0
    with open(input_path) as f:
        data = json.load(f)

        for idb_path, func_addrs in data.items():
            tot_funcs += len(func_addrs)

    print(f'Tot funcs: {tot_funcs}')


def worker_func(j_path, j_idx, j_num):
    assert j_path.endswith('.json')
    output_j_path = join(g_config['jsons_dir'],
                         basename(j_path)[:-5] + '_zeek.json')
    sec_per_j = (time.time() - g_start_time) / (j_idx + 1)
    eta = (j_num - j_idx) * sec_per_j
    if g_config['log_selection']:
        log_worker(f'Considering for analysis: {j_idx+1}/{j_num} {j_path} ({sec_per_j:.3f}s/j, eta: {eta:.3f}s)')

    # check if we need to analyze it
    if isfile(output_j_path):
        if g_config['force']:
            if g_config['log_selection']:
                log_worker(f'Selecting {j_path} (force mode ON)')
        else:
            with open(output_j_path) as f:
                output_j_data = json.load(f)
            with_error, with_timeout = check_result_for_errors(output_j_data)
            if g_config['select_with_error'] and with_error:
                if g_config['log_selection']:
                    log_worker(f'Selecting {j_path} (with errors)')
            elif g_config['select_with_timeout'] and with_timeout:
                if g_config['log_selection']:
                    log_worker(f'Selecting {j_path} (with timeout)')
            else:
                if g_config['log_selection']:
                    log_worker(f'Skipping: {output_j_path}')
                return
        # need to process this JSON even if result is already available. Rename
        # the back up to .old to avoid losing results and improve understanding
        # on what's going on.
        old_output_j_path = output_j_path + '.old'
        shutil.move(output_j_path, old_output_j_path)
    else:
        if g_config['log_selection']:
            log_worker(f'Selected: {j_idx+1}/{j_num} {j_path} (no result json found)')

    log_worker(f'Processing: {j_idx+1}/{j_num} {j_path}')

    with open(j_path) as f:
        j_data = json.load(f)

    results = defaultdict(dict)
    for binary_name, binary_info in j_data.items():
        start_time = time.time()
        if g_debug:
            log_worker(f'Processing {binary_name}')
        arch = binary_info.pop('arch')
        functions = binary_info
        functions_hash_vals = {}
        functions_raw_hashes = {}
        functions_errors = {}
        funcs_num = len(functions)
        for func_idx, (func_addr, func_info) in enumerate(functions.items()):
            if g_config['target_func_addr'] is not None \
                    and g_config['target_func_addr'] != func_addr:
                continue
            if g_debug:
                log_worker(f'Processing function J:{j_idx+1}/{j_num} F:{func_idx+1}/{funcs_num} @ {func_addr}')
            blocks = func_info['basic_blocks']
            func_hash_vals, function_raw_hashes, errors = process_function(
                j_path, binary_name, func_addr,
                func_idx, funcs_num, blocks, arch)
            func_hash_str = hash_vals_to_str(func_hash_vals)
            functions_hash_vals[func_addr] = func_hash_str
            functions_raw_hashes[func_addr] = function_raw_hashes

            if len(errors) > 0:
                functions_errors[func_addr] = errors
            if g_debug:
                log_worker(f'Output function hash vals: {func_hash_str}')
        results[binary_name]['hashes'] = functions_hash_vals
        results[binary_name]['raw_hashes'] = functions_raw_hashes
        results[binary_name]['errors'] = functions_errors
        elapsed_time = time.time() - start_time
        results[binary_name]['elapsed_time'] = elapsed_time

    tot_elapsed_time = time.time() - g_start_time

    if not g_config['dry_run']:
        # safety guard
        assert output_j_path.find('zeek') >= 0
        with open(output_j_path, 'w') as f:
            f.write(json.dumps(results, sort_keys=True,
                               indent=2, separators=(',', ': ')))

        old_output_j_path = output_j_path + '.old'
        if isfile(old_output_j_path):
            os.unlink(old_output_j_path)
    else:
        log.warning('DRY RUN: NOT storing results')

    log_worker(f'Done processing {j_idx+1}/{j_num} {j_path} ({elapsed_time:.3f}s / {tot_elapsed_time:.3f}s)')


def hash_vals_to_str(hash_vals):
    elems = []
    for val, freq in sorted(hash_vals.items()):
        elem = f'{val}:{freq}'
        elems.append(elem)
    out = ';'.join(elems)
    return out


def set_logger(debug, outputdir):
    """
    Set logger level, syntax, and logfile

    Args
        debug: if True, set the log level to DEBUG
        outputdir: path of the output directory for the logfile
    """
    LOG_NAME = 'zeek'

    global log
    log = logging.getLogger(LOG_NAME)

    fh = logging.FileHandler(os.path.join(
        outputdir, '{}.log'.format(LOG_NAME)))
    fh.setLevel(logging.DEBUG)

    fmt = '%(asctime)s %(levelname)s %(message)s'
    formatter = coloredlogs.ColoredFormatter(fmt)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        loglevel = 'DEBUG'
    else:
        loglevel = 'INFO'
    coloredlogs.install(fmt=fmt,
                        level=loglevel,
                        logger=log)


def log_worker(msg, only_file=False):
    msg = msg.strip('\n')
    try:
        process_id = f'P{multiprocessing.current_process()._identity[0]:02d}'
    except Exception:
        process_id = f'P0'
    if not only_file:
        log.info(f'[{process_id}] {msg}')
    with open(join(g_config['logs_dir'], f'{process_id}.log'), 'a') as f:
        f.write(msg + '\n')


def create_error_entry(j_path, binary_name, func_addr, exc):
    error_entry = f'Error:{j_path}@{binary_name}@{func_addr}@{repr(exc)}'
    return error_entry


def create_error_record(j_path, binary_name, func_addr, exc, tb):
    out = f'EXCEPTION RECORD\n'
    out += f'j_path: {j_path}\n'
    out += f'binary name: {binary_name}\n'
    out += f'func addr: {func_addr}\n'
    out += f'Exception: {repr(exc)}\nTB: {tb}\n'
    out += '----------------------\n'
    return out


def check_result_for_errors(output_j_data):
    with_error, with_timeout = False, False
    for binary_name, res in output_j_data.items():
        for func_name, errors in res['errors'].items():
            for error in errors:
                if error.find('timeout') >= 0 \
                        or error.find('release unlocked lock') >= 0:
                    with_timeout = True
                else:
                    with_error = True
    return with_error, with_timeout


def log_worker_error(msg):
    try:
        process_id = multiprocessing.current_process()._identity[0]
    except Exception:
        process_id = 0
    with open(join(g_config['logs_dir'], f'P{process_id}-exceptions.log'), 'a') as f:
        f.write(msg.rstrip('\n')+'\n')


class StrandsExtractor():
    def __init__(self, vex_block, arch):
        self.vex_block = vex_block
        self.statements = vex_block.statements
        self.arch = arch
        self.pyvex_arch = arch_to_pyvex_arch_map[arch]
        self.pwntools_arch = arch_to_pwntools_arch_map[arch]

        self.tmp2exp = {}
        self.reg2exp = defaultdict(list)

        self.norm_reg_names = {}
        self.next_norm_reg_name_idx = 1

        self.HASH_MASK = ((1 << 10) - 1)

        self.start_time = time.time()

    def check_timeout(self):
        elapsed_time = time.time() - self.start_time
        if elapsed_time > g_config['block_timeout']:
            raise Exception('timeout while analzying block')

    def get_norm_reg_name(self, reg):
        norm = self.norm_reg_names.get(reg, None)
        if norm is None:
            norm = f't{self.next_norm_reg_name_idx}'
            self.next_norm_reg_name_idx += 1
            self.norm_reg_names[reg] = norm
        return norm

    def reset_norm_reg_names(self):
        self.next_norm_reg_name_idx = 1
        self.norm_reg_names = {}

    def scan_block(self):
        '''
        Scan block for unsupported statements and operations.
        '''

        for stmt_idx, stmt in enumerate(self.statements):
            if stmt.tag not in supported_vex_stmts:
                log_worker_error(f'unsupported stmt: {stmt.tag}')
                continue

            if stmt.tag == 'Ist_Put':
                self.scan_exp(stmt.data)
            elif stmt.tag == 'Ist_PutI':
                self.scan_exp(stmt.ix)
                self.scan_exp(stmt.data)
            elif stmt.tag == 'Ist_WrTmp':
                self.scan_exp(stmt.data)
            elif stmt.tag == 'Ist_Store':
                self.scan_exp(stmt.addr)
                self.scan_exp(stmt.data)
                pass
            elif stmt.tag in ['Ist_IMark', 'Ist_AbiHint', 'Ist_Dirty']:
                pass
            elif stmt.tag == 'Ist_Exit':
                if stmt.guard is not None:
                    self.scan_exp(stmt.guard)

    def scan_exp(self, exp):
        if exp.tag not in supported_vex_exps:
            log_worker_error(f'unsupported exp: {exp.tag}')
            return

        if exp.tag in ['Iex_Qop', 'Iex_Triop', 'Iex_Binop', 'Iex_Unop']:
            if exp.op not in op_to_norm_op_map.keys():
                found = False
                for op_prefix in op_prefixes_to_norm_op_map.keys():
                    if exp.op.startswith(op_prefix):
                        found = True
                        break
                if not found:
                    log_worker_error(f'unsupported {exp.tag} op: {exp.op}')
        elif exp.tag == 'Iex_Load':
            self.scan_exp(exp.addr)
        else:
            for cexp in exp.child_expressions:
                self.scan_exp(cexp)

    def extract_strands(self):
        if g_debug or g_verbose:
            print('Extracting strands from this VEX block:')
            self.vex_block.pp()

        """
        We first start doing a linear scan of the VEX block and we update the
        following data structures:
        - candidates: list of statement indexes that should be consider as
          starting point of a strand.
        - tmp2exp = {tmp_reg_idx : (IRExpr, stmt_idx)}
            - for each tmp register, store the expression that defines it and
              the index of the statement of such expression
        - reg2exp = {
            reg_offset : [ (IRExpr, stmt_idx), (IRExpr, stmt_idx), ... ]
          }
        """
        candidates = []
        for stmt_idx, stmt in enumerate(self.statements):
            if stmt.tag == 'Ist_WrTmp':
                self.tmp2exp[stmt.tmp] = (stmt.data, stmt_idx)
            elif stmt.tag == 'Ist_Put':
                if not self.should_skip_reg(stmt.offset):
                    self.reg2exp[stmt.offset].append((stmt.data, stmt_idx))
                    candidates.append(stmt_idx)
            elif stmt.tag == 'Ist_PutI':
                candidates.append(stmt_idx)
            elif stmt.tag == 'Ist_Store':
                candidates.append(stmt_idx)
            elif stmt.tag == 'Ist_Dirty':
                self.tmp2exp[stmt.tmp] = ('dirty', stmt_idx)
            elif stmt.tag == 'Ist_CAS':
                self.tmp2exp[stmt.oldLo] = (CustomExpr(
                    'CAS', [stmt.addr, stmt.expdLo]), stmt_idx)
            elif stmt.tag == 'Ist_LLSC':
                if stmt.storedata is not None:
                    self.tmp2exp[stmt.result] = (CustomExpr(
                        'LLSC', [stmt.addr, stmt.storedata]), stmt_idx)
                else:
                    self.tmp2exp[stmt.result] = (
                        CustomExpr('LLSC', [stmt.addr]), stmt_idx)
            elif stmt.tag == 'Ist_LoadG':
                self.tmp2exp[stmt.dst] = (CustomExpr(
                    'Ist_LoadG', [stmt.guard, stmt.addr, stmt.alt]), stmt_idx)
            elif stmt.tag == 'Ist_StoreG':
                candidates.append(stmt_idx)
            elif stmt.tag in ['Ist_IMark', 'Ist_AbiHint', 'Ist_MBE']:
                pass
            elif stmt.tag == 'Ist_Exit':
                if stmt.guard is not None:
                    candidates.append(stmt_idx)
            else:
                raise Exception(f'stmt {stmt.tag} not supported')

        if g_debug or g_verbose:
            print(f'Candidates: {candidates}')

        strands_idxs = []
        strands_hashes = Counter()
        raw_hashes = []
        while len(candidates) > 0:
            start_idx = candidates.pop()
            if g_debug or g_verbose:
                print(f'Current strand idx: {start_idx} {self.statements[start_idx]}')

            strand_idxs, strand_hash, raw_hash = self.extract_strand(start_idx)
            if g_debug or g_verbose:
                print(f'STRAND IDXS: {strand_idxs}')
                print(f'STRAND HASH: {strand_hash}')

            strands_idxs.append(strand_idxs)
            strands_hashes.update((strand_hash, ))
            raw_hashes.append(raw_hash)
            for strand_idx in strand_idxs:
                if strand_idx in candidates:
                    candidates.remove(strand_idx)

        if g_debug:
            print(f'VEX BLOCK STRANDS: {strands_idxs}')
            print(f'VEX BLOCK STRANDS HASHES: {strands_hashes}')
        return strands_idxs, strands_hashes, raw_hashes

    def extract_strand(self, start_idx):
        '''Returns: the list of used '''

        self.check_timeout()

        self.reset_norm_reg_names()

        stmt = self.statements[start_idx]

        if g_debug:
            print(f'extract_strand {start_idx} {stmt}')

        self.curr_strand_idxs = set()
        self.computed_exp_trees = {}
        exp_tree = None
        if stmt.tag == 'Ist_Put':
            exp_tree_l = self.get_norm_reg_name(stmt.offset)
            exp_tree_r = self.extract_strand_from_exp(stmt.data, start_idx)
            exp_tree = ('=', (exp_tree_l, exp_tree_r))
        elif stmt.tag == 'Ist_PutI':
            exp_tree_l = self.extract_strand_from_exp(stmt.ix, start_idx)
            exp_tree_r = self.extract_strand_from_exp(stmt.data, start_idx)
            exp_tree = ('=', (exp_tree_l, exp_tree_r))
        elif stmt.tag == 'Ist_Store':
            exp_addr = self.extract_strand_from_exp(stmt.addr, start_idx)
            exp_data = self.extract_strand_from_exp(stmt.data, start_idx)
            exp_tree = ('memstore', (exp_addr, exp_data))
        elif stmt.tag == 'Ist_StoreG':
            exp_guard = self.extract_strand_from_exp(stmt.guard, start_idx)
            exp_addr = self.extract_strand_from_exp(stmt.addr, start_idx)
            exp_data = self.extract_strand_from_exp(stmt.data, start_idx)
            exp_tree = ('guardedmemstore', (exp_guard, exp_addr, exp_data))
        elif stmt.tag == 'Ist_Exit':
            assert stmt.guard is not None
            exp_tree = self.extract_strand_from_exp(stmt.guard, start_idx)
        else:
            raise Exception(f'starting stmt {stmt.tag} not supported')

        assert exp_tree is not None
        assert type(exp_tree) == tuple
        if g_debug or g_verbose:
            print(f'STRAND EXP TREE: {exp_tree}')
        exp_hash, raw_exp_hash = self.hash_exp_tree(exp_tree)
        return list(sorted(self.curr_strand_idxs)), exp_hash, raw_exp_hash

    def extract_strand_from_exp(self, exp, stmt_idx):
        self.check_timeout()
        if g_debug or g_verbose:
            print(f'extract_strand_from_exp {stmt_idx} {exp}')
        self.curr_strand_idxs.add(stmt_idx)

        if (exp, stmt_idx) in self.computed_exp_trees.keys():
            return self.computed_exp_trees[(exp, stmt_idx)]

        exp_tree = None
        if type(exp) == str:
            exp_tree = exp
        elif exp.tag == 'Iex_RdTmp':
            tmp = exp.tmp
            def_exp, def_exp_idx = self.tmp2exp[tmp]
            exp_tree = self.extract_strand_from_exp(def_exp, def_exp_idx)
        elif exp.tag == 'Iex_Get':
            for put_exp, put_exp_idx in self.reg2exp[exp.offset][::-1]:
                if put_exp_idx < stmt_idx:
                    exp_tree = self.extract_strand_from_exp(
                        put_exp, put_exp_idx)
                    break
            else:
                # there may not be any put_stmt, and that's OK
                if g_debug:
                    print(f'Warning: there was no put statement for {exp.offset} / {self.reg_offset_to_name(exp.offset)}')
                exp_tree = self.get_norm_reg_name(exp.offset)
        elif exp.tag == 'Iex_Binop':
            norm_op = op_to_norm_op(exp.op)
            if norm_op is None:
                raise Exception(f'unsupported {exp.tag} op {exp.op}')
            cexp1_tree = self.extract_strand_from_exp(
                exp.child_expressions[0], stmt_idx)
            cexp2_tree = self.extract_strand_from_exp(
                exp.child_expressions[1], stmt_idx)
            if norm_op in '+*&|^':
                if type(cexp1_tree) == str and type(cexp2_tree) == str:
                    exp_tree = (norm_op, tuple(
                        sorted((cexp1_tree, cexp2_tree))))
                else:
                    exp_tree = (norm_op, tuple((cexp1_tree, cexp2_tree)))
            else:
                exp_tree = (norm_op, tuple((cexp1_tree, cexp2_tree)))
        elif exp.tag == 'Iex_Unop':
            norm_op = op_to_norm_op(exp.op)
            if norm_op is None:
                raise Exception(f'unsupported {exp.tag} op {exp.op}')
            cexp = self.extract_strand_from_exp(
                exp.child_expressions[0], stmt_idx)
            if norm_op == 'cast':
                # ignore casts for now
                exp_tree = cexp
            else:
                exp_tree = (norm_op, (cexp, ))
        elif exp.tag in ['Iex_Triop', 'Iex_Qop']:
            norm_op = op_to_norm_op(exp.op)
            if norm_op is None:
                raise Exception(f'unsupported {exp.tag} op {exp.op}')
            cexp_trees = []
            for cexp in exp.child_expressions:
                cexp_tree = self.extract_strand_from_exp(cexp, stmt_idx)
                cexp_trees.append(cexp_tree)
            exp_tree = (norm_op, tuple(cexp_trees))
        elif exp.tag in ['Iex_CCall', 'Iex_ITE', 'Iex_GetI']:
            cexp_trees = []
            for cexp in exp.child_expressions:
                cexp_tree = self.extract_strand_from_exp(cexp, stmt_idx)
                cexp_trees.append(cexp_tree)
            exp_tree = (exp.tag, tuple(cexp_trees))
        elif exp.tag in ['Iex_Const']:
            exp_tree = str(exp.con.value)
        elif exp.tag == 'Iex_Load':
            exp_addr = self.extract_strand_from_exp(exp.addr, stmt_idx)
            exp_tree = ('memload', ((exp_addr, )))
        elif exp.tag == 'Iex_Custom':
            cexp_trees = []
            for cexp in exp.child_expressions:
                cexp_tree = self.extract_strand_from_exp(cexp, stmt_idx)
                cexp_trees.append(cexp_tree)
            exp_tree = (exp.op, tuple(cexp_trees))
        else:
            raise Exception(f'exp {exp.tag} not supported')

        if g_debug:
            print(f'exp_tree: {stmt_idx} {exp} => {exp_tree}')

        assert exp_tree is not None

        self.computed_exp_trees[(exp, stmt_idx)] = exp_tree

        return exp_tree

    def hash_exp_tree(self, exp_tree):
        signal.alarm(g_config['hash_timeout'])
        try:
            hash_ = hashlib.md5(str(exp_tree).encode('utf-8'))
            raw_hash = hash_.hexdigest()
            shash = u16(hash_.digest()[:2]) & self.HASH_MASK
            signal.alarm(0)
        except ZeekTimeoutException:
            raise Exception('timeout when computing strand hash')
        except Exception:
            signal.alarm(0)
            raise
        return shash, raw_hash

    def reg_offset_to_name(self, offset):
        return self.pyvex_arch.translate_register_name(offset)

    def should_skip_reg(self, offset):
        reg_name = self.reg_offset_to_name(offset)
        if reg_name in ['eip', 'rip', 'pc']:
            return True
        if reg_name.startswith('cc_'):
            return True
        return False


def process_function(j_path, binary_name, func_addr, func_idx, funcs_num, blocks, arch):
    func_hash_vals = Counter()
    function_raw_hashes = {}
    errors = []
    blocks_num = len(blocks)
    if g_config['log_functions']:
        log_worker(f'Processing function {j_path} {func_addr} F:{func_idx+1}/{funcs_num}')
    for block_idx, (block_addr, block_info) in enumerate(sorted(blocks.items())):
        if g_config['log_blocks']:
            only_file = False
        else:
            only_file = True
        if g_config['target_block_addr'] is not None and g_config['target_block_addr'] != block_addr:
            continue
        log_worker(f'Processing block {j_path} {func_addr} F:{func_idx+1}/{funcs_num} B:{block_idx+1}/{blocks_num} @ {block_addr}', only_file=only_file)
        block_bytes_b64 = block_info['b64_bytes']
        if block_bytes_b64 is not None:
            block_bytes = base64.b64decode(block_bytes_b64)
        else:
            context.arch = arch_to_pwntools_arch_map[arch]
            block_bytes = asm('\n'.join(block_info['bb_disasm']))
        expected_strands_idxs = block_info.get('expected_strands_idxs', None)

        try:
            function_raw_hashes[block_addr] = {}
            block_hash_vals, block_raw_hashes = extract_block_hash_vals(
                block_bytes, arch=arch, expected_strands_idxs=expected_strands_idxs)
            func_hash_vals.update(block_hash_vals)
            function_raw_hashes[block_addr] = block_raw_hashes
        except Exception as exc:
            error_entry = create_error_entry(
                j_path, binary_name, func_addr, exc)
            error_record = create_error_record(
                j_path, binary_name, func_addr, exc, traceback.format_exc())
            errors.append(error_entry)
            log_worker_error(error_record)
            if g_config['print_exceptions']:
                print(f'{error_record}')
            if g_config['stop_after_exception']:
                import IPython
                IPython.embed(colors='neutral')
            continue

    return func_hash_vals, function_raw_hashes, errors


def extract_block_hash_vals(block_bytes, arch, expected_strands_idxs=None):
    block_hash_vals = Counter()
    block_raw_hashes = []
    if g_config['debug']:
        log_worker(f'Extracting vex blocks from {len(block_bytes)} bytes')

    signal.alarm(g_config['vex_timeout'])
    try:
        vex_blocks, blocks_bytes = extract_vex_blocks(block_bytes, arch)
        signal.alarm(0)
    except ZeekTimeoutException:
        raise Exception('timeout when extracting VEX block')
    except Exception:
        signal.alarm(0)
        raise Exception('error while lifting VEX block')

    if g_config['debug']:
        log_worker(f'Extracted {len(vex_blocks)} vex blocks')
    if expected_strands_idxs is not None:
        assert len(expected_strands_idxs) == len(vex_blocks)
    vex_blocks_num = len(vex_blocks)
    for vex_block_idx, vex_block in enumerate(vex_blocks):
        se = StrandsExtractor(vex_block, arch)
        if g_config['scan_mode']:
            se.scan_block()
        else:
            block_strands_idxs, vex_block_hashes_vals, raw_hashes = se.extract_strands()

            if expected_strands_idxs is not None:
                assert block_strands_idxs == expected_strands_idxs[vex_block_idx], f'{block_strands_idxs} != {expected_strands_idxs[vex_block_idx]}'

            block_hash_vals.update(vex_block_hashes_vals)
            block_raw_hashes.extend(raw_hashes)

            if g_config['stop_after_vex_block']:
                import IPython
                IPython.embed(colors='neutral')

    return block_hash_vals, block_raw_hashes


def extract_vex_blocks(bytes_, arch, opt_level=2, start_addr=0x400000):
    off = 0
    addr = start_addr
    blocks = []
    block_bytes = []

    while off < len(bytes_):
        irsb = pyvex.lift(
            bytes_[off:], addr, arch_to_pyvex_arch_map[arch], opt_level=opt_level)
        blocks.append(irsb)
        block_bytes.append(bytes_[off:off + irsb.size])
        addr += irsb.size
        off += irsb.size

    return blocks, block_bytes


class CustomExpr():
    """
    Dummy binop expression useful to store references to two expressions
    instead of just one. Useful for CAS and LLSC statements.
    """

    def __init__(self, op, child_expressions):
        self.tag = 'Iex_Custom'
        self.op = op
        self.child_expressions = child_expressions[:]


def alarm_handler(signum, frame):
    if g_config['debug']:
        log_worker('timeout when extracting VEX block')
    raise ZeekTimeoutException()


signal.signal(signal.SIGALRM, alarm_handler)


class ZeekTimeoutException(Exception):
    pass


def op_to_norm_op(op):
    norm_op = op_to_norm_op_map.get(op, None)
    if norm_op is not None:
        return norm_op
    for op_prefix, op_norm in op_prefixes_to_norm_op_map.items():
        if op.startswith(op_prefix):
            return op_norm
    if not g_config['only_known_ops']:
        return op
    return None


class Colors:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


arch_to_pyvex_arch_map = {
    'x86': archinfo.ArchX86(),
    'x86-32': archinfo.ArchX86(),
    'x64': archinfo.ArchAMD64(),
    'x86-64': archinfo.ArchAMD64(),
    'arm32': archinfo.ArchARM(),
    'arm-32': archinfo.ArchARM(),
    'arm64': archinfo.ArchAArch64(),
    'arm-64': archinfo.ArchAArch64(),
    'mips32': archinfo.ArchMIPS32(),
    'mips-32': archinfo.ArchMIPS32(),
    'mips64': archinfo.ArchMIPS64(),
    'mips-64': archinfo.ArchMIPS64(),
}


arch_to_pwntools_arch_map = {
    'x86': 'i386',
    'x86-32': 'i386',
    'x64': 'amd64',
    'x86-64': 'amd64',
    'arm32': 'arm',
    'arm-32': 'arm',
    'arm64': 'aarch64',
    'arm-64': 'aarch64',
    'mips32': 'mips',
    'mips-32': 'mips',
    'mips64': 'mips64',
    'mips-64': 'mips64',
}


op_to_norm_op_map = {
    # binop
    'Iop_Add64': '+',
    'Iop_Add32': '+',
    'Iop_Add16': '+',
    'Iop_Add8': '+',
    'Iop_Add64x2': '+',
    'Iop_Add32x4': '+',
    'Iop_Add16x8': '+',
    'Iop_Add8x16': '+',
    'Iop_Add64F0x2': '+',
    'Iop_Add32F0x4': '+',
    'Iop_Sub64': '-',
    'Iop_Sub32': '-',
    'Iop_Sub16': '-',
    'Iop_Sub8': '-',
    'Iop_Sub32x4': '-',
    'Iop_QSub8Ux16': '-',
    'Iop_Mul64': '*',
    'Iop_Mul64F0x2': '*',
    'Iop_Mul32': '*',
    'Iop_MullU64': '*',
    'Iop_MullS64': '*',
    'Iop_MullU32': '*',
    'Iop_MullS32': '*',
    'Iop_DivU64': '/',
    'Iop_DivModS64to64': '/',
    'Iop_DivModU128to64': '/',
    'Iop_DivModU64to32': '/',
    'Iop_Shr64': '>>',
    'Iop_Shr32': '>>',
    'Iop_Shr16': '>>',
    'Iop_Shr8': '>>',
    'Iop_Shl64': '<<',
    'Iop_Shl32': '<<',
    'Iop_Shl16': '<<',
    'Iop_Shl8': '<<',
    'Iop_Sar64': '>>',
    'Iop_Sar32': '>>',
    'Iop_Sar16': '>>',
    'Iop_Sar8': '>>',
    'Iop_AndV128': '&',
    'Iop_And64': '&',
    'Iop_And32': '&',
    'Iop_And16': '&',
    'Iop_And8': '&',
    'Iop_OrV128': '|',
    'Iop_Or64': '|',
    'Iop_Or32': '|',
    'Iop_Or16': '|',
    'Iop_Or8': '|',
    'Iop_XorV128': '^',
    'Iop_Xor64': '^',
    'Iop_Xor32': '^',
    'Iop_Xor16': '^',
    'Iop_Xor8': '^',
    'Iop_CasCmpNE64': '!=',
    'Iop_CasCmpNE32': '!=',
    'Iop_CasCmpNE16': '!=',
    'Iop_CasCmpNE8': '!=',
    'Iop_CmpNE64': '!=',
    'Iop_CmpNE32': '!=',
    'Iop_CmpNE16': '!=',
    'Iop_CmpNE8': '!=',
    'Iop_CmpEQ64': '==',
    'Iop_CmpEQ32': '==',
    'Iop_CmpEQ16': '==',
    'Iop_CmpEQ8': '==',
    'Iop_CmpEQ64x2': '==',
    'Iop_CmpEQ32x4': '==',
    'Iop_CmpEQ16x8': '==',
    'Iop_CmpEQ8x16': '==',
    'Iop_CmpEQ8x16': '==',
    'Iop_CmpEQ64F0x2': '==',
    'Iop_CmpEQ32F0x4': '==',
    'Iop_CmpLE64U': '<=',
    'Iop_CmpLE64S': '<=',
    'Iop_CmpLE32U': '<=',
    'Iop_CmpLE32S': '<=',
    'Iop_CmpLT64U': '<',
    'Iop_CmpLT64S': '<',
    'Iop_CmpLT32U': '<',
    'Iop_CmpLT32S': '<',
    'Iop_CmpF64': 'comp',
    'Iop_CmpF32': 'comp',
    'Iop_64HLtoV128': 'combine',
    'Iop_64HLto128': 'combine',
    'Iop_32HLto64': 'combine',
    'Iop_16HLto32': 'combine',
    'Iop_8HLto16': 'combine',
    # unop
    'Iop_SetV128lo64': 'cast',
    'Iop_V128to64': 'cast',
    'Iop_V128HIto64': 'cast',
    'Iop_128to64': 'cast',
    'Iop_128HIto64': 'cast',
    'Iop_128to32': 'cast',
    'Iop_128to16': 'cast',
    'Iop_128to8': 'cast',
    'Iop_128to1': 'bool',
    'Iop_64StoV128': 'cast',
    'Iop_64UtoV128': 'cast',
    'Iop_64Sto128': 'cast',
    'Iop_64Uto128': 'cast',
    'Iop_64to32': 'cast',
    'Iop_64HIto32': 'cast',
    'Iop_64to16': 'cast',
    'Iop_64to8': 'cast',
    'Iop_64to1': 'bool',
    'Iop_32StoV128': 'cast',
    'Iop_32UtoV128': 'cast',
    'Iop_32to64': 'cast',
    'Iop_32Sto64': 'cast',
    'Iop_32Uto64': 'cast',
    'Iop_32to16': 'cast',
    'Iop_32HIto16': 'cast',
    'Iop_32to8': 'cast',
    'Iop_32to1': 'cast',
    'Iop_32to1': 'bool',
    'Iop_16Sto64': 'cast',
    'Iop_16Uto64': 'cast',
    'Iop_16Sto32': 'cast',
    'Iop_16Uto32': 'cast',
    'Iop_16to8': 'cast',
    'Iop_16HIto8': 'cast',
    'Iop_16to1': 'bool',
    'Iop_8Sto64': 'cast',
    'Iop_8Uto64': 'cast',
    'Iop_8Sto32': 'cast',
    'Iop_8Uto32': 'cast',
    'Iop_8Sto16': 'cast',
    'Iop_8Uto16': 'cast',
    'Iop_8to1': 'bool',
    'Iop_1Sto64': 'int',
    'Iop_1Uto64': 'int',
    'Iop_1Sto32': 'int',
    'Iop_1Uto32': 'int',
    'Iop_1Sto16': 'int',
    'Iop_1Uto16': 'int',
    'Iop_1Sto8': 'int',
    'Iop_1Uto8': 'int',
    'Iop_ReinterpI64asF64': 'float',
    'Iop_ReinterpF64asI64': 'int',
    'Iop_ReinterpI32asF32': 'float',
    'Iop_ReinterpF32asI32': 'int',
    'Iop_F64toF32': 'cast',
    'Iop_F64toI64S': 'int',
    'Iop_F64toI64U': 'int',
    'Iop_F64toI32S': 'int',
    'Iop_F64toI32U': 'int',
    'Iop_I64StoF64': 'float',
    'Iop_I64UtoF64': 'float',
    'Iop_I64StoF32': 'float',
    'Iop_I64UtoF32': 'float',
    'Iop_I32StoF64': 'float',
    'Iop_I32UtoF64': 'float',
    'Iop_I32StoF32': 'float',
    'Iop_I32UtoF32': 'float',
    'Iop_F32toF64': 'float',
    'Iop_F32toF64S': 'float',
    'Iop_F32toI64S': 'int',
    'Iop_NotV128': '!',
    'Iop_Not128': '!',
    'Iop_Not64': '!',
    'Iop_Not32': '!',
    'Iop_Not16': '!',
    'Iop_Not8': '!',
    'Iop_Not1': '!',
    'Iop_NegF64': 'neg',
    'Iop_NegF32': 'neg',
    'Iop_Neg64Fx2': 'neg',
    'Iop_Clz64': 'countzero',
    'Iop_Clz32': 'countzero',
    'Iop_Ctz64': 'countzero',
    'Iop_Ctz32': 'countzero',
    'Iop_MAddF64': 'muladd',
    'Iop_MSubF64': 'mulsub',
}


op_prefixes_to_norm_op_map = {
    'Iop_Add': '+',
    'Iop_Sub': '-',
    'Iop_Mul': '*',
    'Iop_Div': '/',
    'Iop_And': '&',
    'Iop_Or': '|',
    'Iop_Xor': '^',
    'Iop_Not': '!',
    'Iop_CmpNE': '!=',
    'Iop_CmpEQ': '==',
    'Iop_CmpLT': '<',
    'Iop_CmpLE': '<=',
    'Iop_CmpGT': '>',
    'Iop_CmpGE': '>=',
    'Iop_ExpCmpNE': '!=',
    'Iop_ExpCmpEQ': '==',
    'Iop_ExpCmpLT': '<',
    'Iop_ExpCmpLE': '<=',
    'Iop_ExpCmpGT': '>',
    'Iop_ExpCmpGE': '>=',
    'Iop_Cat': 'combine',
    'Iop_Interleave': 'combine',
    'Iop_Max': 'max',
    'Iop_Min': 'min',
    'Iop_Perm': 'perm',
    'Iop_Round': 'round',
    'Iop_Sar': '>>',
    'Iop_Shr': '>>',
    'Iop_Shl': '<<',
    'Iop_Sh': '<<',
    'Iop_Rsh': '>>',
    'Iop_Sqrt': 'sqrt',
    'Iop_Cnt': 'count',
    'Iop_Neg': 'neg',
    'Iop_Reinterp': 'cast',
    'Iop_Zero': 'cast',
    'Iop_Abs': 'abs',
    'Iop_NarrowUn': 'cast',
    'Iop_QNarrow': 'cast',
    'Iop_Reverse': 'reverse',
    'Iop_Slice': 'slice',
    'Iop_GetMSB': 'conv',
    'Iop_Scale': 'scale',
}


supported_vex_stmts = set([
    'Ist_WrTmp',
    'Ist_Put',
    'Ist_PutI',
    'Ist_Store',
    'Ist_IMark',
    'Ist_AbiHint',
    'Ist_Exit',
    'Ist_LoadG',
    'Ist_StoreG',
    'Ist_Dirty',
    'Ist_CAS',
    'Ist_LLSC',
    'Ist_MBE',
])


supported_vex_exps = set([
    'Iex_RdTmp',
    'Iex_Get',
    'Iex_GetI',
    'Iex_Qop',
    'Iex_Triop',
    'Iex_Binop',
    'Iex_Unop',
    'Iex_Const',
    'Iex_Load',
    'Iex_ITE',
    'Iex_CCall',
])


if __name__ == '__main__':
    cli()
