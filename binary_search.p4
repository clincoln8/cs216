/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    bit next_hop;  // local variable
	bit<8> final_out;

     /**
      * Indicates that a packet is dropped by setting the
      * output port to the DROP_PORT
      */
      action drop() {
          //TODO
      }


	action lookup(bit final_hop){
	// final_out = final_hop;
	// TODO
}
	
	table table2a {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
              lookup;
         }
         size = 1024;
         default_action = drop;
     }
	table table2b {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
              lookup;
         }
         size = 1024;
         default_action = drop;
     }
	table table2c {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
              lookup;
         }
         size = 1024;
         default_action = drop;
     }
	table table2d {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
              lookup;
         }
         size = 1024;
         default_action = drop;
     }


      action nhop(bit hop) {
         next_hop = hop;
}
			

     table table1a {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
              nhop;
         }
         size = 1024;
         default_action = drop;
     }
     table table1b {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
			nhop;
         }
         size = 1024;
         default_action = drop;
     }
			

     /**
      * Computes address of next IPv4 hop and output port
      * based on the IPv4 destination of the current packet.
      * Decrements packet IPv4 TTL.
      * @param nextHop IPv4 address of next hop
      */
     table table0 {
         key = { headers.ip.dstAddr: lpm; }  // longest-prefix match
         actions = {
              drop;
              nhop;
         }
         size = 1024;
         default_action = drop;
     }

apply {

          table0.apply(); // Match result will go into nextHop
          if(nhop == 0){ 
          
          table1a.apply();
          if (nhop == 0) table2a.apply();
          if (nhop == 1) table2b.apply();
          
          }
          if(nhop == 1){ table1b.apply();
		if (nhop == 0) table2c.apply();		
		if (nhop == 1) table2d.apply();
          }
          
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
