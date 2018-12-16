/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	2007/08/21:
 *				Declare utility functions for CLNP packet
 *				processing
 *		Tadeus:		2008/03/30:
 *				Bringing all function prototypes to this file
 *				except those declared static
 *				Putting all function documentations in
 *				kernel-doc style (kernel-doc nano-HOWTO)
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_CLNP_H
#define _NET_CLNP_H

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/datalink.h>

/*
 * Functions provided by af_atn.c
 */

/**
 * get_nsap_addr - returns the NSAP address of this host in addr
 * @addr: an array of size NSAP_ADDR_LEN to hold this host's NSAP address
 */
void get_nsap_addr(__u8 *addr) __attribute__ ((nonnull));

/*
 * Functions provided by clnp_input.c
 */

/**
 * clnp_local_deliver_finish - sets skb->data to point to the transport header
 *
 * The pointer of skb->h.raw points to the skb->data
 */
extern void clnp_local_deliver_finish(struct sk_buff *skb);

/**
 * clnp_local_deliver
 *
 * Reassemblies the segmented PDUs if needed and then they are passed to the
 * transport layer. The reassembly function is called only if it is needed.
 */
extern void clnp_local_deliver(struct sk_buff *skb, struct clnphdr *clnph
				       , struct clnp_segment *seg, int ms_flag);

/**
 * clnp_rcv_finish - analyzes the optional parts
 *
 * Print error messages and call clnp_discard function if there is any error
 * detected. Analyze whether to call local delivery or source routing function.
 */
extern void clnp_rcv_finish(struct sk_buff *skb, struct clnphdr *clnph
			    , struct clnp_segment *seg, int fas_len, int sp_flag
				     , int ms_flag, int er_flag, int type_flag);


/**
 * clnp_rcv - performs sanity check on the datagram
 *
 * Call clnp_discard function if there is any error detected.
 * Return 0 if everything is okay.
 * Return -REASON if any error is detected (REASON is one of those listed on
 * include/linux/clnp.h under PDU error codes).
 */
extern int clnp_rcv(struct sk_buff *skb, struct net_device *dev
			 , struct packet_type *pt, struct net_device *orig_dev);

/**
 * is_our_dgram - checks if the received packet's dest addr is the same as ours
 *
 * Return 1 if the address is the same (i.e., the packet is for us).
 * Return 0 if the address is different (i.e., the packet is not for us).
 */
extern int is_our_dgram(struct clnphdr *clnph, __u8 *my_addr);

/**
 * clnp_addr_ck - checks the lengths of the destination and source addresses
 *
 * Return 1 if each of the lengths is exactly 20.
 * Return 0 if not all of the lengths is exactly 20.
 */
extern int clnp_addr_ck (struct clnphdr *clnph);

/*
 * Functions provided by clnp_csum.c
 */

/**
 * clnp_gen_csum - generates checksum of a CLNP header
 * @clnph: the &clnphdr whose checksum field is to be filled in
 *
 * This function calculates the checksum over the whole length of the specified
 * @clnph.
 */
extern void clnp_gen_csum(struct clnphdr *clnph);

/**
 * clnp_check_csum - performs an error detection on a CLNP header
 * @clnph: the &clnphdr to be checked
 *
 * Return 0 if checksum calculation succeed (no error detected).
 * Return -GEN_BADCSUM if checksum calculation failed (error detected).
 */
extern int clnp_check_csum(struct clnphdr *clnph);

/**
 * clnp_adjust_csum - adjusts the checksum parameter when an octet is altered
 * @clnph: the &clnphdr whose checksum field is to be adjusted
 * @idx_changed: the index of the value in @clnph to be changed from old to new
 * @new_value: the new value of the octet to be altered
 * @old_value: the existing value of the octet to be altered
 *
 * This is useful when the value of the TTL field must be changed.
 * Return 0 if the existing @clnph has correct checksum.
 * Return -GEN_BADCSUM if the existing @clnph has incorrect checksum.
 */
extern int clnp_adjust_csum(struct clnphdr *clnph, int idx_changed
					      , __u8 new_value, __u8 old_value);

/*
 * Functions provided by clnp_err.c
 */

/**
 * clnp_discard - discards a PDU and sends back an error report PDU if possible
 * @skb: the CLNP PDU to be discarded
 * @reason: the reason why the PDU is discarded
 * @location: the location in the PDU's header at which the error was detected
 * @gfp_mask: work priority
 *
 * If this function is called from an interrupt @gfp_mask must be %GFP_ATOMIC.
 */
extern int clnp_discard(struct sk_buff *skb, __u8 reason, __u8 location
							      , gfp_t gfp_mask);

/*
 * Functions provided by clnp_fragment.c
 */

/**
 * clnp_defrag - reassemblies CLNP datagrams
 *
 * Return NULL if the datagram contained in @skb is segmented and the datagram
 * is not the last fragment to complete the whole initial datagram.
 */
extern struct sk_buff *clnp_defrag(struct sk_buff *skb);

/**
 * clnp_comp_frag - inserts a segment into its place overcoming overlap
 */
extern void clnp_insert_frag(struct clnp_fragment_list *cfl, struct sk_buff *skb
						    , struct clnp_segment *seg);

/**
 * clnp_comp_frag - checks whether all segments have been received completely
 */
extern struct sk_buff *clnp_comp_frag(struct clnp_fragment_list *cfh
						       , unsigned short totlen);

/**
 * clnp_frag_destroy - removes a fragment list and its fragments
 *
 * The fragment list is also removed from the queue.
 * This function is called after all the segments have been reconstructed or
 * when the timer has expired.
 */
extern void clnp_frag_destroy(struct clnp_fragment_list *cfh);

/**
 * clnp_frag_expires - called when the reassembly timer expired
 */
extern void clnp_frag_expires(unsigned long data);

/*
 * Functions provided by clnp_util.c
 */

/**
 * clnp_hdr - returns the CLNP header part of an &sk_buff
 */
static __always_inline struct clnphdr *clnp_hdr(struct sk_buff *skb)
{
	return (struct clnphdr *) skb->h.raw;
}

/**
 * set_clnp_flag - returns the value for CLNP header flag field
 */
static __always_inline __u8 set_clnp_flag(__u8 sp, __u8 ms, __u8 er, __u8 type)
{
	return sp << 7 | ms << 6 | er << 5 | type;
}

/**
 * clnp_decrease_ttl - decreases the value of TTL field in CLNP header by one
 */
static __always_inline __u8 clnp_decrease_ttl(struct clnphdr *clnph)
{
	return --(clnph->ttl);
}

/**
 * cmp_nsap - returns true if @nsap1 == @nsap2 or false if @nsap1 != @nsap2
 */
static __always_inline int cmp_nsap(__u8 *nsap1, __u8 *nsap2)
{
	int i = NSAP_ADDR_LEN;

	while (--i >= 0) {
		if (nsap1 [i] != nsap2 [i]) {
			return false;
		}
	}

	return true;
}

/**
 * atn_skb_headroom - returns the size of the headroom an &sk_buff should have
 * @dev: the device through which the &sk_buff will be sent out
 */
static __always_inline int atn_skb_headroom(struct net_device *dev)
{
	extern struct datalink_proto *p8022_datalink;

	return LL_RESERVED_SPACE_EXTRA(dev, p8022_datalink->header_length);
}

#endif /* _NET_CLNP_H */
