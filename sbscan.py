#!/usr/bin/env python3
"""
This script is intended to scan block devices for various superblocks

Currently supported:
    - ext4
    - md-raid metadata 1.x
""" 

import struct
import sys
import os

SECTOR_SIZE = 512

EXT_MAGIC = 0xef53
EXT_MAGIC_OFFSET = 0x38

MD_MAGIC = 0xa92b4efc
MD_MAGIC_OFFSET = 0x0

def get_ext4_state(state):
    switch = {
        0: "not clean",
        1: "clean",
        2: "errors",
        4: "recovered orphans"
    }
    return switch.get(state, "Unknown")


def print_ext_info(sector, sector_pos):
    state = struct.unpack_from("@H", sector, 0x3a)[0]
    if get_ext4_state(state) == "Unknown":
        return False
    else:
        bs_power = struct.unpack_from("@I", sector, 0x18)[0]
        if bs_power > 10:
            return False
        blocksize = 2 ** bs_power 
        if blocksize > 64:
            return False
        blockcount = struct.unpack_from("@I", sector, 0x04)[0]
        current_block = sector_pos // (blocksize * 2)
        block_alignment_msg = ""
        block_alignment = sector_pos % (blocksize * 2)
        if current_block > 1 and block_alignment != 0:
            block_alignment_msg = " seems wrong [rem=%d]" % block_alignment
        first_block = struct.unpack_from("@I", sector, 0x14)[0]
        print("ext2/3/4 @ sector %d (block %d%s) " % 
              (sector_pos, current_block, block_alignment_msg) + 
              "[%s, block_size: %d kb, block_count: %d, first_bl: %d]" %
              (get_ext4_state(state),
               blocksize,
               blockcount,
               first_block))
    return True


def print_md_info(sector, sector_pos):
    sb_ver = struct.unpack_from("@I", sector, 0x04)[0]
    if sb_ver != 1:
        return False
    rlevel = struct.unpack_from("@I", sector, 0x48)[0]
    num_disks = struct.unpack_from("@I", sector, 0x5c)[0]
    size = struct.unpack_from("@I", sector, 0x50)[0]
    print("md-raid @ sector %d (sb_ver=%d) [level=%d, disks=%d, size=%d kb]" % 
          (sector_pos, sb_ver, rlevel, num_disks, size//2))
    return True


def scan_file(filename):
    sector_pos = 0
    with open(filename, "rb") as fhandle:
        try:
            sector = fhandle.read(SECTOR_SIZE)
            while sector:
                # Is this sector part of an ext2/3/4 superblock?
                magic = struct.unpack_from("@H", sector, EXT_MAGIC_OFFSET)[0]
                if  magic == EXT_MAGIC:
                    print_ext_info(sector, sector_pos)

                # Does this sector contain a Linux md-RAID superblock?
                magic = struct.unpack_from("@I", sector, MD_MAGIC_OFFSET)[0]
                if  magic == MD_MAGIC:
                    print_md_info(sector, sector_pos)
                
                sector = fhandle.read(SECTOR_SIZE)
                sector_pos += 1
        except KeyboardInterrupt:
            print("Stopped. Bye!")
        finally:
            fhandle.close()
            sys.exit(1)


if len(sys.argv) < 2:
    print("Scan block devices for superblocks\nUsage: " + sys.argv[0] + \
            " <block device>")
    sys.exit(1)

if (os.geteuid() != 0):
    print("Root permissions required!")
    sys.exit(1)

print("Scanning...")
scan_file(sys.argv[1])
print("...Done")
