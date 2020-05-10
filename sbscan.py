#!/usr/bin/env python3
"""
This script is intended to scan block devices for various superblocks

Currently supported:
    - mbr partition tables
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

MBR_MAGIC = 0xaa55
MBR_MAGIC_OFFSET = 0x01fe
MBR_PART_OFFSET = 0x1be

def get_ext4_state(state):
    switch = {
        0: "not clean",
        1: "clean",
        2: "errors",
        4: "recovered orphans"
    }
    return switch.get(state, "unknown")


def print_ext_info(sector, sector_pos):
    state = struct.unpack_from("@H", sector, 0x3a)[0]
    if get_ext4_state(state) == "unknown":
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
            block_alignment_msg = " misaligned [%d]" % block_alignment
        first_block = struct.unpack_from("@I", sector, 0x14)[0]
        print("ext2/3/4 @ sector %d (block %d%s) " % 
              (sector_pos, 
               current_block, 
               block_alignment_msg) + 
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


def get_partition_type(ptype):
    switch = {
        b'\x00': "empty",
        b'\x05': "extended",
        b'\x06': "fat16",
        b'\x07': "hpfs/ntfs/exfat",
        b'\x0b': "w95 fat32",
        b'\x0c': "w95 fat32 (lba)",
        b'\x0e': "w95 fat16 (lba)",
        b'\x0f': "w95 ext. (lba)",
        b'\x11': "hidden fat12",
        b'\x14': "hidden fat16 <3",
        b'\x16': "hidden fat16",
        b'\x17': "hidden hpfs/ntf",
        b'\x27': "hidden ntfs win",
        b'\x82': "linux swap",
        b'\x83': "linux",
        b'\x85': "linux extended",
        b'\x86': "ntfs",
        b'\x87': "ntfs",
        b'\x88': "linux plain text",
        b'\x8e': "linux lvm",
        b'\x9f': "bsd/os",
        b'\xa5': "freebsd",
        b'\xa6': "openbsd",
        b'\xa9': "netbsd",
        b'\xda': "no file system",
        b'\xee': "gpt",
        b'\xef': "efi",
        b'\xfb': "vmware vmfs",
        b'\xfc': "vmware vmkcore",
        b'\xfd': "linux raid-auto"
    }
    return switch.get(ptype, "unknown")


def print_mbr_info(sector, sector_pos):
    p_str = ""
    for i in range(4):
        ptype = struct.unpack_from("@c", 
                                   sector, 
                                   MBR_PART_OFFSET + (i * 0x10) + 0x04)[0]
        pt = get_partition_type(ptype)
        if pt == "unknown":
            return False
        elif pt == "empty":
            pass
        else:
            psize = struct.unpack_from("@I", 
                                       sector, 
                                       MBR_PART_OFFSET + (i * 0x10) + 0x0c)[0]
            pstart = struct.unpack_from("@I", 
                                        sector, 
                                        MBR_PART_OFFSET + (i * 0x10) + 0x08)[0]
            p_str += "[p%d:%s|start:%d,sz:%d]" % (i + 1, pt, pstart, psize)
    if p_str == "":
        return False
    print("mbr @ sector %d (partitions: %s)" % (sector_pos, p_str))
    return True


def scan_file(filename):
    sector_pos = 0
    with open(filename, "rb") as fhandle:
        try:
            sector = fhandle.read(SECTOR_SIZE)
            while sector:
                # Is this a master boot record?
                magic = struct.unpack_from("@H", sector, MBR_MAGIC_OFFSET)[0]
                if  magic == MBR_MAGIC:
                    print_mbr_info(sector, sector_pos)

                # Is this sector part of an ext2/3/4 superblock?
                magic = struct.unpack_from("@H", sector, EXT_MAGIC_OFFSET)[0]
                if  magic == EXT_MAGIC:
                    print_ext_info(sector, sector_pos)

                # Does this sector contain a Linux md-RAID 1.x superblock?
                magic = struct.unpack_from("@I", sector, MD_MAGIC_OFFSET)[0]
                if  magic == MD_MAGIC:
                    print_md_info(sector, sector_pos)
                
                sector = fhandle.read(SECTOR_SIZE)
                sector_pos += 1
        except KeyboardInterrupt:
            print("...Stopped @ sector %d (~%d kb examined). Bye!" % 
                  (sector_pos,
                   (sector_pos * SECTOR_SIZE) // 1024 ))
            fhandle.close()
            sys.exit(1)
    fhandle.close()
    return sector_pos


if len(sys.argv) < 2:
    print("Scan block devices for superblocks\nUsage: " + sys.argv[0] + \
            " <block device>")
    sys.exit(1)

if (os.geteuid() != 0):
    print("Root permissions required!")
    sys.exit(1)

print("Scanning...")
n_sectors = scan_file(sys.argv[1])
print("...Done [%d sectors (%d kb) examined]" % 
      (n_sectors,
       (n_sectors * SECTOR_SIZE) // 1024))
