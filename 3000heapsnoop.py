#! /usr/bin/env python3

# 3000heapsnoop: Snooping virtual to physical mapping of heap allocations in userspace
# Copyright (C) 2020  William Findlay
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# The BPF program used here is based on memleak.py from bcc tools:
# https://github.com/iovisor/bcc/blob/master/tools/memleak.py

import os, sys
import argparse
import time
import signal
import atexit
import subprocess
import struct
import math

from bcc import BPF

# Path to the BPF program source file
PROJECT_PATH = os.path.dirname(os.path.realpath(__file__))
BPF_PROGRAM_PATH = os.path.realpath(os.path.join(PROJECT_PATH, 'bpf_program.c'))

# Get page size from sysconf
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
# Get page shift from page size
PAGE_SHIFT = int(math.log(PAGE_SIZE, 2))

DESCRIPTION = """
Snooping virtrual to physical mapping of heap allocations in userspace.
Created by William Findlay for teaching purposes.
"""
EPILOG = """
Example usage:
    sudo ./3000heapsnoop.py --comm 3000malloc # Trace all allocations by 3000malloc
    sudo ./3000heapsnoop.py --pid 12374       # Trace all allocations by pid 12374
    sudo ./3000heapsnoop.py                   # Trace all allocations systemwide (not recommended)
"""

def print_formatted_items(*args, header=0):
    """
    Print items according to the specified row format.
    """
    row_format = "{:>8} {:>16} {:>16}"
    if not header:
        row_format += " -> "
    else:
        row_format += "    "
    row_format += "{:<16} {:>8}"
    print(row_format.format(*args))

def on_exit(bpf):
    """
    Run exit hooks.
    Register this with atexit below.
    """
    print("All done!", file=sys.stderr)

def read_pagemap(pid, offset, size=8):
  with open(f"/proc/{pid}/pagemap", 'rb') as f:
    f.seek(offset, 0)
    return struct.unpack('Q', f.read(size))[0]

def get_physical_mapping(pid, virt):
    """
    Attempt to get the physical mapping for address virt.
    """
    # Convert virtual address to decimal for easier arithmetic
    dec_virt = int(virt, 16)
    try:
        # Calculate the correct offset
        offset = (dec_virt // PAGE_SIZE) * 8
        # Read the correct entry from the pagemap
        entry = read_pagemap(pid, offset)
        # Obtain page frame number by taking the least significant 54 bits
        pfn = entry & 0x007FFFFFFFFFFFFF
        # Calculate the physical address
        phys = (pfn << PAGE_SHIFT) + (dec_virt % PAGE_SIZE)
        # Convert physical address to a hex string
        return str(hex(phys))[2:].zfill(16)
    except:
        return "UNKNOWN"

def trace_print(bpf):
    """
    A non-blocking version of bcc's trace_print.
    """
    while True:
        fields = bpf.trace_fields(nonblocking=True)
        msg = fields[-1]
        if msg == None:
            return
        print(msg.decode('utf-8'), file=sys.stderr)

def attach_uprobes(bpf, sym, pid):
    bpf.attach_uprobe(name="c", sym=sym, fn_name=sym+'_enter', pid=pid)
    bpf.attach_uretprobe(name="c", sym=sym, fn_name=sym+'_exit', pid=pid)

def register_perf_buffers(bpf):
    """
    Register perf buffers with BPF program.
    """
    def allocation_events(cpu, data, size):
        # Read event data from perf buffer
        v = bpf["allocation_events"].event(data)

        # Prepare virtual and physical address for printing
        virt = str(hex(v.virt))[2:].zfill(16)
        #phys = get_physical_mapping(v.pid, virt)
        phys = str(hex(v.phys))[2:].zfill(16)

        # Print information
        print_formatted_items(v.pid, v.comm.decode('utf-8'), virt, phys, v.size)
    bpf["allocation_events"].open_perf_buffer(allocation_events, page_cnt=2**5)

if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    filters = parser.add_mutually_exclusive_group()
    filters.add_argument('--pid', type=int,
            help='trace a specific pid')
    filters.add_argument('--comm', type=str,
            help='trace a specific comm')
    parser.add_argument('--debug', action='store_true',
            help='Read output from bpf_trace_printk as well as perf buffers')
    args = parser.parse_args()

    # Check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    # Register signal handlers that invoke sys.exit
    signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

    # Read bpf program
    with open(BPF_PROGRAM_PATH, 'r') as f:
        text = f.read()

    # Set flags
    flags = []
    flags.append(f"-I{PROJECT_PATH}")
    if args.pid:
        flags.append(f"-DHEAPSNOOP_PID={args.pid}")
    if args.comm:
        flags.append(f"-DHEAPSNOOP_COMM=\"{args.comm}\"")
    if args.debug:
        flags.append(f"-DHEAPSNOOP_DEBUG")

    # Load bpf program
    bpf = BPF(text=text, cflags=flags)
    pid = -1 if not args.pid else args.pid
    attach_uprobes(bpf, "malloc", pid)
    attach_uprobes(bpf, "calloc", pid)
    register_perf_buffers(bpf)
    atexit.register(on_exit, bpf)

    print("Tracing process memory, ctrl-c to quit...", file=sys.stderr)
    print_formatted_items("PID", "COMM", "VIRT ADDR", "PHYS ADDR", "SIZE", header=1)
    while True:
        if args.debug:
            trace_print(bpf)
        bpf.perf_buffer_poll()
        time.sleep(1)
