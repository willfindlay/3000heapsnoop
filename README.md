# 3000heapsnoop

Snooping virtual to physical mapping of heap allocations in userspace.

## Credits

Inspiration for BPF program component taken from [memleak.py](https://github.com/iovisor/bcc/blob/master/tools/memleak.py)

## Requirements

- Linux 4.9+
- [bcc for Python3](https://github.com/iovisor/bcc)

## Usage

This is a simple tool for teaching purposes. It is meant to illustrate that virtual memory may be contiguous
while physical memory is almost certainly not.

Run `sudo ./3000heapsnoop.py --comm <comm>` to trace all processes named \<comm\>. **Processes that are being traced must either be running continuously or sleep long enough after allocation to read pagemappings from procfs.**

## Installation

Run `sudo make install` after cloning this repo. Then you can run with just `3000heapsnoop`.
