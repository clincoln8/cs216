#include <core.p4>
#include <v1model.p4>


#include "includes/headers.p4"
#include "includes/metadata.p4"

/* Constants */

// Num Prefix Lengths
#define HHH_TABCOUNT 32

#define HASH_ENTRY_SIZE 66 // hash_entry format: [33 bits encoded prefix][1 bit longer exists][32 bits next hop]

// Lookup table size in each stage // TODO update tabsize for new hash entry
#define HHH_TABSIZE 32w8192 

// Size of registers
#define HHH_REGSIZE HHH_TABSIZE*HHH_TABCOUNT+1

// Bitvector length
#define HHH_VECSIZE 32

// extend ip to 33 bits for prefix encoding
#define EXTENDER 33w0x100000000

/* Hash Metadata */
struct hhh_metadata_t {
    bit<HHH_VECSIZE> vector;  // bitvector of valid stages

    bit<HASH_ENTRY_SIZE> new_hash_entry;

    bit<32> key; // key used in next hop search (typically dstAddr)

    bit<33> cur_prefix;  // 33 bit encoded matching prefix
    bit<8> cur_len; 

    bit<32> h1_idx; // hash1 = crc32
    bit<32> h2_idx; // hash2 = identity 

    bit<1> need_table_query;
    bit<32> next_hop;

    bit<4> hash_hits; // [h1_read][h2_read][h1_write][h2_write] (use to detect hits and collision

    // CRC Hash indices
    bit<32> h1_len_00_idx;  // computed index for stage 00
    bit<32> h1_len_01_idx;  // computed index for stage 01
    bit<32> h1_len_02_idx;  // computed index for stage 02
    bit<32> h1_len_03_idx;  // computed index for stage 03
    bit<32> h1_len_04_idx;  // computed index for stage 04
    bit<32> h1_len_05_idx;  // computed index for stage 05
    bit<32> h1_len_06_idx;  // computed index for stage 06
    bit<32> h1_len_07_idx;  // computed index for stage 07
    bit<32> h1_len_08_idx;  // computed index for stage 08
    bit<32> h1_len_09_idx;  // computed index for stage 09
    bit<32> h1_len_10_idx;  // computed index for stage 10
    bit<32> h1_len_11_idx;  // computed index for stage 11
    bit<32> h1_len_12_idx;  // computed index for stage 12
    bit<32> h1_len_13_idx;  // computed index for stage 13
    bit<32> h1_len_14_idx;  // computed index for stage 14
    bit<32> h1_len_15_idx;  // computed index for stage 15
    bit<32> h1_len_16_idx;  // computed index for stage 16
    bit<32> h1_len_17_idx;  // computed index for stage 17
    bit<32> h1_len_18_idx;  // computed index for stage 18
    bit<32> h1_len_19_idx;  // computed index for stage 19
    bit<32> h1_len_20_idx;  // computed index for stage 20
    bit<32> h1_len_21_idx;  // computed index for stage 21
    bit<32> h1_len_22_idx;  // computed index for stage 22
    bit<32> h1_len_23_idx;  // computed index for stage 23
    bit<32> h1_len_24_idx;  // computed index for stage 24
    bit<32> h1_len_25_idx;  // computed index for stage 25
    bit<32> h1_len_26_idx;  // computed index for stage 26
    bit<32> h1_len_27_idx;  // computed index for stage 27
    bit<32> h1_len_28_idx;  // computed index for stage 28
    bit<32> h1_len_29_idx;  // computed index for stage 29
    bit<32> h1_len_30_idx;  // computed index for stage 30
    bit<32> h1_len_31_idx;  // computed index for stage 31
    bit<32> h1_len_32_idx;  // computed index for stage 32

    // Random Hash indices
    bit<32> h2_len_00_idx;  // computed index for stage 00
    bit<32> h2_len_01_idx;  // computed index for stage 01
    bit<32> h2_len_02_idx;  // computed index for stage 02
    bit<32> h2_len_03_idx;  // computed index for stage 03
    bit<32> h2_len_04_idx;  // computed index for stage 04
    bit<32> h2_len_05_idx;  // computed index for stage 05
    bit<32> h2_len_06_idx;  // computed index for stage 06
    bit<32> h2_len_07_idx;  // computed index for stage 07
    bit<32> h2_len_08_idx;  // computed index for stage 08
    bit<32> h2_len_09_idx;  // computed index for stage 09
    bit<32> h2_len_10_idx;  // computed index for stage 10
    bit<32> h2_len_11_idx;  // computed index for stage 11
    bit<32> h2_len_12_idx;  // computed index for stage 12
    bit<32> h2_len_13_idx;  // computed index for stage 13
    bit<32> h2_len_14_idx;  // computed index for stage 14
    bit<32> h2_len_15_idx;  // computed index for stage 15
    bit<32> h2_len_16_idx;  // computed index for stage 16
    bit<32> h2_len_17_idx;  // computed index for stage 17
    bit<32> h2_len_18_idx;  // computed index for stage 18
    bit<32> h2_len_19_idx;  // computed index for stage 19
    bit<32> h2_len_20_idx;  // computed index for stage 20
    bit<32> h2_len_21_idx;  // computed index for stage 21
    bit<32> h2_len_22_idx;  // computed index for stage 22
    bit<32> h2_len_23_idx;  // computed index for stage 23
    bit<32> h2_len_24_idx;  // computed index for stage 24
    bit<32> h2_len_25_idx;  // computed index for stage 25
    bit<32> h2_len_26_idx;  // computed index for stage 26
    bit<32> h2_len_27_idx;  // computed index for stage 27
    bit<32> h2_len_28_idx;  // computed index for stage 28
    bit<32> h2_len_29_idx;  // computed index for stage 29
    bit<32> h2_len_30_idx;  // computed index for stage 30
    bit<32> h2_len_31_idx;  // computed index for stage 31
    bit<32> h2_len_32_idx;  // computed index for stage 32
}

/* Dleft Ingress Processing */
control process_dleft(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Hash metadata instance
    hhh_metadata_t hhh;

    // prefix hash registers
    register<bit<HASH_ENTRY_SIZE>>(HHH_REGSIZE) h1_reg; // crc32 hash
    register<bit<HASH_ENTRY_SIZE>>(HHH_REGSIZE) h2_reg; // identity


    // Compute hash index for each possible prefix - helper function
    @name("hash_compute") action hash_compute() {

        // Compute crc hashes for different prefix lenghts
        hhh.h1_len_00_idx = HHH_REGSIZE-1;
        hash(hhh.h1_len_01_idx, HashAlgorithm.crc32,  0*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 31 }, HHH_TABSIZE);
        hash(hhh.h1_len_02_idx, HashAlgorithm.crc32,  1*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 30 }, HHH_TABSIZE);
        hash(hhh.h1_len_03_idx, HashAlgorithm.crc32,  2*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 29 }, HHH_TABSIZE);
        hash(hhh.h1_len_04_idx, HashAlgorithm.crc32,  3*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 28 }, HHH_TABSIZE);
        hash(hhh.h1_len_05_idx, HashAlgorithm.crc32,  4*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 27 }, HHH_TABSIZE);
        hash(hhh.h1_len_06_idx, HashAlgorithm.crc32,  5*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 26 }, HHH_TABSIZE);
        hash(hhh.h1_len_07_idx, HashAlgorithm.crc32,  6*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 25 }, HHH_TABSIZE);
        hash(hhh.h1_len_08_idx, HashAlgorithm.crc32,  7*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 24 }, HHH_TABSIZE);
        hash(hhh.h1_len_09_idx, HashAlgorithm.crc32,  8*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 23 }, HHH_TABSIZE);
        hash(hhh.h1_len_10_idx, HashAlgorithm.crc32,  9*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 22 }, HHH_TABSIZE);
        hash(hhh.h1_len_11_idx, HashAlgorithm.crc32, 10*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 21 }, HHH_TABSIZE);
        hash(hhh.h1_len_12_idx, HashAlgorithm.crc32, 11*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 20 }, HHH_TABSIZE);
        hash(hhh.h1_len_13_idx, HashAlgorithm.crc32, 12*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 19 }, HHH_TABSIZE);
        hash(hhh.h1_len_14_idx, HashAlgorithm.crc32, 13*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 18 }, HHH_TABSIZE);
        hash(hhh.h1_len_15_idx, HashAlgorithm.crc32, 14*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 17 }, HHH_TABSIZE);
        hash(hhh.h1_len_16_idx, HashAlgorithm.crc32, 15*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 16 }, HHH_TABSIZE);
        hash(hhh.h1_len_17_idx, HashAlgorithm.crc32, 16*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 15 }, HHH_TABSIZE);
        hash(hhh.h1_len_18_idx, HashAlgorithm.crc32, 17*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 14 }, HHH_TABSIZE);
        hash(hhh.h1_len_19_idx, HashAlgorithm.crc32, 18*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 13 }, HHH_TABSIZE);
        hash(hhh.h1_len_20_idx, HashAlgorithm.crc32, 19*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 12 }, HHH_TABSIZE);
        hash(hhh.h1_len_21_idx, HashAlgorithm.crc32, 20*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 11 }, HHH_TABSIZE);
        hash(hhh.h1_len_22_idx, HashAlgorithm.crc32, 21*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 10 }, HHH_TABSIZE);
        hash(hhh.h1_len_23_idx, HashAlgorithm.crc32, 22*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  9 }, HHH_TABSIZE);
        hash(hhh.h1_len_24_idx, HashAlgorithm.crc32, 23*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  8 }, HHH_TABSIZE);
        hash(hhh.h1_len_25_idx, HashAlgorithm.crc32, 24*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  7 }, HHH_TABSIZE);
        hash(hhh.h1_len_26_idx, HashAlgorithm.crc32, 25*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  6 }, HHH_TABSIZE);
        hash(hhh.h1_len_27_idx, HashAlgorithm.crc32, 26*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  5 }, HHH_TABSIZE);
        hash(hhh.h1_len_28_idx, HashAlgorithm.crc32, 27*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  4 }, HHH_TABSIZE);
        hash(hhh.h1_len_29_idx, HashAlgorithm.crc32, 28*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  3 }, HHH_TABSIZE);
        hash(hhh.h1_len_30_idx, HashAlgorithm.crc32, 29*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  2 }, HHH_TABSIZE);
        hash(hhh.h1_len_31_idx, HashAlgorithm.crc32, 30*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  1 }, HHH_TABSIZE);
        hash(hhh.h1_len_32_idx, HashAlgorithm.crc32, 31*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  0 }, HHH_TABSIZE);

        // Compute hash2 indices for different prefix lenghts
        hhh.h2_len_00_idx = HHH_REGSIZE-1;
        hash(hhh.h2_len_01_idx, HashAlgorithm.identity,  0*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 31 }, HHH_TABSIZE);
        hash(hhh.h2_len_02_idx, HashAlgorithm.identity,  1*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 30 }, HHH_TABSIZE);
        hash(hhh.h2_len_03_idx, HashAlgorithm.identity,  2*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 29 }, HHH_TABSIZE);
        hash(hhh.h2_len_04_idx, HashAlgorithm.identity,  3*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 28 }, HHH_TABSIZE);
        hash(hhh.h2_len_05_idx, HashAlgorithm.identity,  4*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 27 }, HHH_TABSIZE);
        hash(hhh.h2_len_06_idx, HashAlgorithm.identity,  5*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 26 }, HHH_TABSIZE);
        hash(hhh.h2_len_07_idx, HashAlgorithm.identity,  6*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 25 }, HHH_TABSIZE);
        hash(hhh.h2_len_08_idx, HashAlgorithm.identity,  7*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 24 }, HHH_TABSIZE);
        hash(hhh.h2_len_09_idx, HashAlgorithm.identity,  8*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 23 }, HHH_TABSIZE);
        hash(hhh.h2_len_10_idx, HashAlgorithm.identity,  9*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 22 }, HHH_TABSIZE);
        hash(hhh.h2_len_11_idx, HashAlgorithm.identity, 10*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 21 }, HHH_TABSIZE);
        hash(hhh.h2_len_12_idx, HashAlgorithm.identity, 11*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 20 }, HHH_TABSIZE);
        hash(hhh.h2_len_13_idx, HashAlgorithm.identity, 12*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 19 }, HHH_TABSIZE);
        hash(hhh.h2_len_14_idx, HashAlgorithm.identity, 13*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 18 }, HHH_TABSIZE);
        hash(hhh.h2_len_15_idx, HashAlgorithm.identity, 14*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 17 }, HHH_TABSIZE);
        hash(hhh.h2_len_16_idx, HashAlgorithm.identity, 15*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 16 }, HHH_TABSIZE);
        hash(hhh.h2_len_17_idx, HashAlgorithm.identity, 16*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 15 }, HHH_TABSIZE);
        hash(hhh.h2_len_18_idx, HashAlgorithm.identity, 17*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 14 }, HHH_TABSIZE);
        hash(hhh.h2_len_19_idx, HashAlgorithm.identity, 18*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 13 }, HHH_TABSIZE);
        hash(hhh.h2_len_20_idx, HashAlgorithm.identity, 19*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 12 }, HHH_TABSIZE);
        hash(hhh.h2_len_21_idx, HashAlgorithm.identity, 20*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 11 }, HHH_TABSIZE);
        hash(hhh.h2_len_22_idx, HashAlgorithm.identity, 21*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >> 10 }, HHH_TABSIZE);
        hash(hhh.h2_len_23_idx, HashAlgorithm.identity, 22*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  9 }, HHH_TABSIZE);
        hash(hhh.h2_len_24_idx, HashAlgorithm.identity, 23*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  8 }, HHH_TABSIZE);
        hash(hhh.h2_len_25_idx, HashAlgorithm.identity, 24*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  7 }, HHH_TABSIZE);
        hash(hhh.h2_len_26_idx, HashAlgorithm.identity, 25*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  6 }, HHH_TABSIZE);
        hash(hhh.h2_len_27_idx, HashAlgorithm.identity, 26*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  5 }, HHH_TABSIZE);
        hash(hhh.h2_len_28_idx, HashAlgorithm.identity, 27*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  4 }, HHH_TABSIZE);
        hash(hhh.h2_len_29_idx, HashAlgorithm.identity, 28*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  3 }, HHH_TABSIZE);
        hash(hhh.h2_len_30_idx, HashAlgorithm.identity, 29*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  2 }, HHH_TABSIZE);
        hash(hhh.h2_len_31_idx, HashAlgorithm.identity, 30*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  1 }, HHH_TABSIZE);
        hash(hhh.h2_len_32_idx, HashAlgorithm.identity, 31*HHH_TABSIZE, { (EXTENDER | (bit<1>)0++hhh.key) >>  0 }, HHH_TABSIZE);
    }

    // Look up hash entry for each possible prefix length - helper function
    @name("hash_lookup") action hash_lookup() {

        // Read validity bits and construct bitvectors
        bit<HASH_ENTRY_SIZE> hash_val;
        hhh.vector = 0;

        h1_reg.read(hash_val, hhh.h1_len_01_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 31 ) { hhh.vector = hhh.vector | 32w0x80000000; }
        h1_reg.read(hash_val, hhh.h1_len_02_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 30 ) { hhh.vector = hhh.vector | 32w0x40000000; }
        h1_reg.read(hash_val, hhh.h1_len_03_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 29 ) { hhh.vector = hhh.vector | 32w0x20000000; }
        h1_reg.read(hash_val, hhh.h1_len_04_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 28 ) { hhh.vector = hhh.vector | 32w0x10000000; }
        h1_reg.read(hash_val, hhh.h1_len_05_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 27 ) { hhh.vector = hhh.vector | 32w0x08000000; }
        h1_reg.read(hash_val, hhh.h1_len_06_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 26 ) { hhh.vector = hhh.vector | 32w0x04000000; }
        h1_reg.read(hash_val, hhh.h1_len_07_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 25 ) { hhh.vector = hhh.vector | 32w0x02000000; }
        h1_reg.read(hash_val, hhh.h1_len_08_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 24 ) { hhh.vector = hhh.vector | 32w0x01000000; }
        h1_reg.read(hash_val, hhh.h1_len_09_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 23 ) { hhh.vector = hhh.vector | 32w0x00800000; }
        h1_reg.read(hash_val, hhh.h1_len_10_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 22 ) { hhh.vector = hhh.vector | 32w0x00400000; }
        h1_reg.read(hash_val, hhh.h1_len_11_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 21 ) { hhh.vector = hhh.vector | 32w0x00200000; }
        h1_reg.read(hash_val, hhh.h1_len_12_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 20 ) { hhh.vector = hhh.vector | 32w0x00100000; }
        h1_reg.read(hash_val, hhh.h1_len_13_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 19 ) { hhh.vector = hhh.vector | 32w0x00080000; }
        h1_reg.read(hash_val, hhh.h1_len_14_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 18 ) { hhh.vector = hhh.vector | 32w0x00040000; }
        h1_reg.read(hash_val, hhh.h1_len_15_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 17 ) { hhh.vector = hhh.vector | 32w0x00020000; }
        h1_reg.read(hash_val, hhh.h1_len_16_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 16 ) { hhh.vector = hhh.vector | 32w0x00010000; }
        h1_reg.read(hash_val, hhh.h1_len_17_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 15 ) { hhh.vector = hhh.vector | 32w0x00008000; }
        h1_reg.read(hash_val, hhh.h1_len_18_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 14 ) { hhh.vector = hhh.vector | 32w0x00004000; }
        h1_reg.read(hash_val, hhh.h1_len_19_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 13 ) { hhh.vector = hhh.vector | 32w0x00002000; }
        h1_reg.read(hash_val, hhh.h1_len_20_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 12 ) { hhh.vector = hhh.vector | 32w0x00001000; }
        h1_reg.read(hash_val, hhh.h1_len_21_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 11 ) { hhh.vector = hhh.vector | 32w0x00000800; }
        h1_reg.read(hash_val, hhh.h1_len_22_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 10 ) { hhh.vector = hhh.vector | 32w0x00000400; }
        h1_reg.read(hash_val, hhh.h1_len_23_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 9 ) { hhh.vector = hhh.vector | 32w0x00000200; }
        h1_reg.read(hash_val, hhh.h1_len_24_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 8 ) { hhh.vector = hhh.vector | 32w0x00000100; }
        h1_reg.read(hash_val, hhh.h1_len_25_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 7 ) { hhh.vector = hhh.vector | 32w0x00000080; }
        h1_reg.read(hash_val, hhh.h1_len_26_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 6 ) { hhh.vector = hhh.vector | 32w0x00000040; }
        h1_reg.read(hash_val, hhh.h1_len_27_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 5 ) { hhh.vector = hhh.vector | 32w0x00000020; }
        h1_reg.read(hash_val, hhh.h1_len_28_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 4 ) { hhh.vector = hhh.vector | 32w0x00000010; }
        h1_reg.read(hash_val, hhh.h1_len_29_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 3 ) { hhh.vector = hhh.vector | 32w0x00000008; }
        h1_reg.read(hash_val, hhh.h1_len_30_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 2 ) { hhh.vector = hhh.vector | 32w0x00000004; }
        h1_reg.read(hash_val, hhh.h1_len_31_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 1 ) { hhh.vector = hhh.vector | 32w0x00000002; }
        h1_reg.read(hash_val, hhh.h1_len_32_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 0 ) { hhh.vector = hhh.vector | 32w0x00000001; }

        h2_reg.read(hash_val, hhh.h2_len_01_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 31 ) { hhh.vector = hhh.vector | 32w0x80000000; }
        h2_reg.read(hash_val, hhh.h2_len_02_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 30 ) { hhh.vector = hhh.vector | 32w0x40000000; }
        h2_reg.read(hash_val, hhh.h2_len_03_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 29 ) { hhh.vector = hhh.vector | 32w0x20000000; }
        h2_reg.read(hash_val, hhh.h2_len_04_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 28 ) { hhh.vector = hhh.vector | 32w0x10000000; }
        h2_reg.read(hash_val, hhh.h2_len_05_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 27 ) { hhh.vector = hhh.vector | 32w0x08000000; }
        h2_reg.read(hash_val, hhh.h2_len_06_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 26 ) { hhh.vector = hhh.vector | 32w0x04000000; }
        h2_reg.read(hash_val, hhh.h2_len_07_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 25 ) { hhh.vector = hhh.vector | 32w0x02000000; }
        h2_reg.read(hash_val, hhh.h2_len_08_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 24 ) { hhh.vector = hhh.vector | 32w0x01000000; }
        h2_reg.read(hash_val, hhh.h2_len_09_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 23 ) { hhh.vector = hhh.vector | 32w0x00800000; }
        h2_reg.read(hash_val, hhh.h2_len_10_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 22 ) { hhh.vector = hhh.vector | 32w0x00400000; }
        h2_reg.read(hash_val, hhh.h2_len_11_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 21 ) { hhh.vector = hhh.vector | 32w0x00200000; }
        h2_reg.read(hash_val, hhh.h2_len_12_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 20 ) { hhh.vector = hhh.vector | 32w0x00100000; }
        h2_reg.read(hash_val, hhh.h2_len_13_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 19 ) { hhh.vector = hhh.vector | 32w0x00080000; }
        h2_reg.read(hash_val, hhh.h2_len_14_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 18 ) { hhh.vector = hhh.vector | 32w0x00040000; }
        h2_reg.read(hash_val, hhh.h2_len_15_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 17 ) { hhh.vector = hhh.vector | 32w0x00020000; }
        h2_reg.read(hash_val, hhh.h2_len_16_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 16 ) { hhh.vector = hhh.vector | 32w0x00010000; }
        h2_reg.read(hash_val, hhh.h2_len_17_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 15 ) { hhh.vector = hhh.vector | 32w0x00008000; }
        h2_reg.read(hash_val, hhh.h2_len_18_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 14 ) { hhh.vector = hhh.vector | 32w0x00004000; }
        h2_reg.read(hash_val, hhh.h2_len_19_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 13 ) { hhh.vector = hhh.vector | 32w0x00002000; }
        h2_reg.read(hash_val, hhh.h2_len_20_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 12 ) { hhh.vector = hhh.vector | 32w0x00001000; }
        h2_reg.read(hash_val, hhh.h2_len_21_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 11 ) { hhh.vector = hhh.vector | 32w0x00000800; }
        h2_reg.read(hash_val, hhh.h2_len_22_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 10 ) { hhh.vector = hhh.vector | 32w0x00000400; }
        h2_reg.read(hash_val, hhh.h2_len_23_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 9 ) { hhh.vector = hhh.vector | 32w0x00000200; }
        h2_reg.read(hash_val, hhh.h2_len_24_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 8 ) { hhh.vector = hhh.vector | 32w0x00000100; }
        h2_reg.read(hash_val, hhh.h2_len_25_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 7 ) { hhh.vector = hhh.vector | 32w0x00000080; }
        h2_reg.read(hash_val, hhh.h2_len_26_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 6 ) { hhh.vector = hhh.vector | 32w0x00000040; }
        h2_reg.read(hash_val, hhh.h2_len_27_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 5 ) { hhh.vector = hhh.vector | 32w0x00000020; }
        h2_reg.read(hash_val, hhh.h2_len_28_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 4 ) { hhh.vector = hhh.vector | 32w0x00000010; }
        h2_reg.read(hash_val, hhh.h2_len_29_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 3 ) { hhh.vector = hhh.vector | 32w0x00000008; }
        h2_reg.read(hash_val, hhh.h2_len_30_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 2 ) { hhh.vector = hhh.vector | 32w0x00000004; }
        h2_reg.read(hash_val, hhh.h2_len_31_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 1 ) { hhh.vector = hhh.vector | 32w0x00000002; }
        h2_reg.read(hash_val, hhh.h2_len_32_idx); if (hash_val[65:33] == (EXTENDER | (bit<1>)0++hhh.key) >> 0 ) { hhh.vector = hhh.vector | 32w0x00000001; }

    }

    // choose prefix index for hash1 according the length - helper function
    @name("h1_index") action h1_index(out bit<32> h1_idx, bit<8> pref_len) {

        /* Unknown value */ { h1_idx = hhh.h1_len_00_idx; }
        if (pref_len ==  1) { h1_idx = hhh.h1_len_01_idx; } 
        if (pref_len ==  2) { h1_idx = hhh.h1_len_02_idx; } 
        if (pref_len ==  3) { h1_idx = hhh.h1_len_03_idx; } 
        if (pref_len ==  4) { h1_idx = hhh.h1_len_04_idx; } 
        if (pref_len ==  5) { h1_idx = hhh.h1_len_05_idx; } 
        if (pref_len ==  6) { h1_idx = hhh.h1_len_06_idx; } 
        if (pref_len ==  7) { h1_idx = hhh.h1_len_07_idx; } 
        if (pref_len ==  8) { h1_idx = hhh.h1_len_08_idx; } 
        if (pref_len ==  9) { h1_idx = hhh.h1_len_09_idx; } 
        if (pref_len == 10) { h1_idx = hhh.h1_len_10_idx; }
        if (pref_len == 11) { h1_idx = hhh.h1_len_11_idx; } 
        if (pref_len == 12) { h1_idx = hhh.h1_len_12_idx; } 
        if (pref_len == 13) { h1_idx = hhh.h1_len_13_idx; } 
        if (pref_len == 14) { h1_idx = hhh.h1_len_14_idx; } 
        if (pref_len == 15) { h1_idx = hhh.h1_len_15_idx; } 
        if (pref_len == 16) { h1_idx = hhh.h1_len_16_idx; } 
        if (pref_len == 17) { h1_idx = hhh.h1_len_17_idx; } 
        if (pref_len == 18) { h1_idx = hhh.h1_len_18_idx; } 
        if (pref_len == 19) { h1_idx = hhh.h1_len_19_idx; } 
        if (pref_len == 20) { h1_idx = hhh.h1_len_20_idx; }
        if (pref_len == 21) { h1_idx = hhh.h1_len_21_idx; } 
        if (pref_len == 22) { h1_idx = hhh.h1_len_22_idx; } 
        if (pref_len == 23) { h1_idx = hhh.h1_len_23_idx; } 
        if (pref_len == 24) { h1_idx = hhh.h1_len_24_idx; } 
        if (pref_len == 25) { h1_idx = hhh.h1_len_25_idx; } 
        if (pref_len == 26) { h1_idx = hhh.h1_len_26_idx; } 
        if (pref_len == 27) { h1_idx = hhh.h1_len_27_idx; } 
        if (pref_len == 28) { h1_idx = hhh.h1_len_28_idx; } 
        if (pref_len == 29) { h1_idx = hhh.h1_len_29_idx; } 
        if (pref_len == 30) { h1_idx = hhh.h1_len_30_idx; }
        if (pref_len == 31) { h1_idx = hhh.h1_len_31_idx; } 
        if (pref_len == 32) { h1_idx = hhh.h1_len_32_idx; }
    }


    // choose prefix index for hash2 according the length - helper function
    @name("h2_index") action h2_index(out bit<32> h2_idx, bit<8> pref_len) {

        /* Unknown value */ { h2_idx = hhh.h2_len_00_idx; }
        if (pref_len ==  1) { h2_idx = hhh.h2_len_01_idx; } 
        if (pref_len ==  2) { h2_idx = hhh.h2_len_02_idx; } 
        if (pref_len ==  3) { h2_idx = hhh.h2_len_03_idx; } 
        if (pref_len ==  4) { h2_idx = hhh.h2_len_04_idx; } 
        if (pref_len ==  5) { h2_idx = hhh.h2_len_05_idx; } 
        if (pref_len ==  6) { h2_idx = hhh.h2_len_06_idx; } 
        if (pref_len ==  7) { h2_idx = hhh.h2_len_07_idx; } 
        if (pref_len ==  8) { h2_idx = hhh.h2_len_08_idx; } 
        if (pref_len ==  9) { h2_idx = hhh.h2_len_09_idx; } 
        if (pref_len == 10) { h2_idx = hhh.h2_len_10_idx; }
        if (pref_len == 11) { h2_idx = hhh.h2_len_11_idx; } 
        if (pref_len == 12) { h2_idx = hhh.h2_len_12_idx; } 
        if (pref_len == 13) { h2_idx = hhh.h2_len_13_idx; } 
        if (pref_len == 14) { h2_idx = hhh.h2_len_14_idx; } 
        if (pref_len == 15) { h2_idx = hhh.h2_len_15_idx; } 
        if (pref_len == 16) { h2_idx = hhh.h2_len_16_idx; } 
        if (pref_len == 17) { h2_idx = hhh.h2_len_17_idx; } 
        if (pref_len == 18) { h2_idx = hhh.h2_len_18_idx; } 
        if (pref_len == 19) { h2_idx = hhh.h2_len_19_idx; } 
        if (pref_len == 20) { h2_idx = hhh.h2_len_20_idx; }
        if (pref_len == 21) { h2_idx = hhh.h2_len_21_idx; } 
        if (pref_len == 22) { h2_idx = hhh.h2_len_22_idx; } 
        if (pref_len == 23) { h2_idx = hhh.h2_len_23_idx; } 
        if (pref_len == 24) { h2_idx = hhh.h2_len_24_idx; } 
        if (pref_len == 25) { h2_idx = hhh.h2_len_25_idx; } 
        if (pref_len == 26) { h2_idx = hhh.h2_len_26_idx; } 
        if (pref_len == 27) { h2_idx = hhh.h2_len_27_idx; } 
        if (pref_len == 28) { h2_idx = hhh.h2_len_28_idx; } 
        if (pref_len == 29) { h2_idx = hhh.h2_len_29_idx; } 
        if (pref_len == 30) { h2_idx = hhh.h2_len_30_idx; }
        if (pref_len == 31) { h2_idx = hhh.h2_len_31_idx; }
        if (pref_len == 32) { h2_idx = hhh.h2_len_32_idx; }
    }


    // Longest Match Prefix Length from Hash Found - pe_tab action
    @name("found_hash_lpm") action found_hash_lpm(bit<8> cur_len) {
        hhh.cur_len = cur_len;        
        hhh.cur_prefix =  (bit<33>)((EXTENDER | (bit<1>)0++hhh.key) >> (32-hhh.cur_len)); 
        h1_index(hhh.h1_idx, hhh.cur_len);
        h2_index(hhh.h2_idx, hhh.cur_len);
    }

    // Parse a single Hash Entry into Prefix, Longer Exists Bit, and Next Hop - helper function
    @name("parse_hash_val") action parse_hash_val(bit<HASH_ENTRY_SIZE> hash_val) {

        hhh.need_table_query = 1;

        bit<33> prefix = hash_val[65:33];
        bit<1> longer_exists = hash_val[32:32];
        bit<32> next_hop = hash_val[31:0];

        if(prefix == hhh.cur_prefix && longer_exists == 0 ) {
            hhh.need_table_query = 0;
            hhh.next_hop = next_hop;
        }
    }

    // Match from full LPM table found - prefix_tab action
    @name("lpm_table_match") action lpm_table_match(bit<8> cur_len, bit<1> longer_exists, bit<32> next_hop) {
        hhh.cur_len = cur_len;
        hhh.next_hop = next_hop;

        // compute hhh.hash_entry by concatenation
        hhh.cur_prefix =  (bit<33>)((EXTENDER | (bit<1>)0++hhh.key) >> (32-hhh.cur_len)); 
        hhh.new_hash_entry = hhh.cur_prefix ++ longer_exists ++ next_hop; 

    }

    // Drop - prefix_tab action
    @name("drop") action drop() {
        mark_to_drop(standard_metadata);
    }

    // Forward - forward_tab action
    @name("forward") action forward(bit<48> dst_mac, bit<9> egress_port) {
        hdr.ethernet.dstAddr = dst_mac;
        standard_metadata.egress_spec = egress_port;
    }

    // HHH priority encoder table
    @name("pe_tab") table pe_tab {
        actions = { found_hash_lpm; }
        default_action = found_hash_lpm(0);
        key = { hhh.vector: ternary; }
    }

    // HHH lookup table
    @name("prefix_tab") table prefix_tab {
        actions = { lpm_table_match; drop; }
        default_action = drop();
        key = { hhh.key: lpm; }
    }

    // HHH lookup table
    @name("forward_tab") table forward_tab {
        actions = { forward; }
        key = { meta.next_hop: exact; }
    }

    apply {

        hhh.need_table_query = 1;    
        hhh.next_hop = 0;
        hhh.cur_prefix = 0;
        hhh.cur_len = 0;

        hhh.key = hdr.ipv4.dstAddr; // value used in tables to determine next hop

        // Compute hash indices
        hash_compute();

        // Index into Hash Tables
        hash_lookup(); 

        // Find Hashed Longest Match
        pe_tab.apply();

        bit<HASH_ENTRY_SIZE> temp;

        if(hhh.cur_len > 0){

            // check for hash1 match
            h1_reg.read(temp, hhh.h1_idx);
            parse_hash_val(temp);

            // check for hash2 match
            if(hhh.need_table_query == 1) {
                h2_reg.read(temp, hhh.h2_idx);
                parse_hash_val(temp);
            }
        }

        // Search prefix table and add to hash (if necessary)
        if(hhh.need_table_query == 1) {
            hhh.new_hash_entry = 0;
            prefix_tab.apply();

            h1_reg.read(temp, hhh.h1_idx);
            if(temp ==  0) {

                // Write to CRC Hash
                h1_reg.write(hhh.h1_idx, hhh.new_hash_entry);

            } else{

                h2_reg.read(temp, hhh.h2_idx);

                if(temp == 0) {
                    // Write to Random Hash
                    h2_reg.write(hhh.h2_idx, hhh.new_hash_entry);        
                } else{
                    // Double Collision
                }
            }
        }

        // Set next ethernet hop based on next hop
        meta.next_hop = hhh.next_hop;
        forward_tab.apply();
    }
}

/* Parser Block */
parser ParserImpl(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/* Ingress Control Block */
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_dleft") process_dleft() process_dleft_0;

    apply {
        // Process HHH if IP header valid
        if (hdr.ipv4.isValid()) { process_dleft_0.apply(hdr, meta, standard_metadata);}
    }
}

/* Verify Checksum */
control verifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {}
}

/* Egress Control Block */
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {}
}

/* Compute Checksum */
control computeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
