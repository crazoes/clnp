/*
 * ATN		CLNP fragment module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		- 2008/04/06:
 *				* Replace all invocation of masking() with
 *				(& CNF_*)
 *				- 2008/04/13:
 *				* Replace all instances of `nh' that is used to
 *				get the CLNP header part with clnp_hdr()
 *				* Replace dev_alloc_skb() with alloc_skb() to
 *				have the correct semantic as it is written in
 *				Linux Network Internals in section 2.1.5.1.
 *				Allocating memory: alloc_skb and dev_alloc_skb:
 *				"dev_alloc_skb is the buffer allocation function
 *				meant for use by device drivers and expected to
 *				be executed in interrupt mode."
 *				- 2008/04/14:
 *				* Replace merge_chars_to_short() with
 *				ntohs(clnph->seglen)
 *				* Replace the following construct
 *				#if defined(__BIG_ENDIAN_BITFIELD)
 *				...
 *				#elif defined(__LITTLE_ENDIAN_BITFIELD)
 *				...
 *				#else
 *				...
 *				#endif
 *				with the equivalent htons()
 *				- 2008/04/19:
 *				* malloc() for cfl in clnp_new_pkt() was not
 *				checked for failure (check added)
 *				- 2008/04/26:
 *				* Replace the custom queue linked-list structure
 *				with the Linux linked-list structure
 *				(linux/list.h)
 *
 * Todo:
 *		Tadeus:		- 2008/04/06:
 *				* In clnp_new_pkt()
 *				* In clnp_comp_frag()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <asm/bug.h>
#include <asm/types.h>
#include <linux/byteorder/generic.h>
#include <linux/clnp.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <net/clnp.h>

/* Private Function Prototypes */
static struct clnp_fragl *clnp_new_pkt(struct sk_buff *skb);
static struct clnp_fragl *clnp_find(struct sk_buff *skb);

/* clnpq is the queue of fragment lists */
static HLIST_HEAD(clnpq);

void clnp_frag_destroy(struct clnp_fragl *cfh)
{
	struct clnp_frag *frag_p = NULL;
	struct clnp_frag *next_p = NULL;
	struct clnp_fragl *scan = NULL;

	printk(KERN_INFO "Entering clnp_frag_destroy()\n");

	/* remove cfh from the list of fragmented PDUs */
	printk(KERN_INFO "Unlink the fragment list from the queue\n");
	if (clnp_frags == cfh) {
		clnp_frags = cfh->next;
	} else {
		for (scan = clnp_frags; scan != NULL; scan = scan->next) {
			if (scan->next == cfh) {
				scan->next = cfh->next;
				break;
			}
		}
	}
	--clnp_fragl_nqueues;

	frag_p = cfh->cfl_frags;
	while (frag_p != NULL) {
		next_p = frag_p->next;
		kfree(frag_p);
		frag_p = next_p;
	}

	printk(KERN_INFO "Fragment list discarded\n");
	kfree(cfh);

	printk(KERN_INFO "The number of CLNP Frag queues: %d\n"
							  , clnp_fragl_nqueues);
}

void clnp_frag_expires(unsigned long data)
{
	struct clnp_fragl *expired = (struct clnp_fragl *) data;
	struct clnp_frag *first_frag = expired->cfl_frags;

	printk(KERN_INFO "Reassembly timer expired for fragment ID: 0x%04X\n"
								 , expired->id);

	if (expired->complete == 1) {
		printk(KERN_INFO "The frag list is complete for fragment ID:"
						      " 0x%04X\n", expired->id);
		return;
	}

	clnp_discard(expired->cfl_orihdr, TTL_EXPREASS);

	clnp_frag_destroy(expired);
}

void concatenate(struct sk_buff *skb, struct clnp_frag *cfr)
{
	struct clnphdr *clnph = clnp_hdr(skb);
	unsigned int fraglen = cfr->last - cfr->first + 1;

	memcpy(skb->data, cfr->data, fraglen);
	skb->data += fraglen - 1;

	clnph->seglen = htons(ntohs(clnph->seglen)
						    + (unsigned short) fraglen);
}

/*
 * clnp_find - finds the corresponding fragment list of a given @skb
 *
 * The search criteria are based on:
 * (1) the identifier found in the segmentation part of the CLNP header,
 * (2) the source address, and
 * (3) the destination address.
 * Linear search is used. It has not been optimized yet. Maybe later it can be
 * improved by using hash algorithm, or even rb-tree maybe?
 */
static struct clnp_fragl *clnp_find(struct sk_buff *skb)
{
	struct clnphdr *clnph = clnp_hdr(skb);
	struct clnp_fragl *node = NULL;

	list_for_each_entry(node, clnp_frags, next) {
		if (node->id == ntohs(clnph->next_part->id) && memcmp(node->)
	}

	cfh = clnp_frags;
	while (cfh != NULL) {
		if ((cfh->id == ntohs(seg->id))
					   && compare_addr(cfh->dstaddr, dest)
					   && compare_addr(cfh->srcaddr, src)) {
			printk(KERN_INFO "Fragment is found.\n");
			return cfh;
		} else {
			cfh = cfh->next;
		}
	}

	printk(KERN_INFO "Fragment is not found.\n");
	return NULL;
}

/*
 * clnp_new_pkt - creates a new fragment list (struct clnp_fragl)
 */
static struct clnp_fragl *clnp_new_pkt(struct sk_buff *skb)
{
	struct clnphdr *clnph = clnp_hdr(skb);
	struct clnp_fragl *cfl = NULL;
	struct clnphdr *orig_clnph = NULL;

	if(skb) {
		cfl = (struct clnp_fragl *) kmalloc(sizeof(struct clnp_fragl)
								  , GFP_ATOMIC);
		if (!cfl) {
			return NULL;
		}
		cfl->cfl_orihdr = alloc_skb(sizeof(struct sk_buff)
								, GFP_ATOMIC);
		orig_clnph = clnp_hdr(cfl->cfl_orihdr);
		orig_clnph = (unsigned char *) kmalloc(
				sizeof(unsigned char) * clnph->hdrlen
								, GFP_KERNEL);
		memcpy(&orig_clnph->nlpid, &clnph->nlpid
							, clnph->hdrlen);

		cfl->id = ntohs(seg->id);
		printk(KERN_INFO "cfl->id: 0x%02X\n",cfl->id);

		memcpy(cfl->dstaddr, clnph->dest_addr, NSAP_ADDR_LEN);
		memcpy(cfl->srcaddr, clnph->src_addr, NSAP_ADDR_LEN);

		cfl->ttl = clnph->ttl;
		cfl->last = ntohs(seg->tot_len) - clnph->hdrlen - 1
									       ;
		cfl->cfl_frags = NULL;
		cfl->next = clnp_frags;
		clnp_frags = cfl;
		clnp_fragl_nqueues++;

		init_timer(&cfl->timer);
		cfl->timer.expires = jiffies + CLNP_FRAG_TIME;
		cfl->timer.data = (unsigned long) cfl;
		cfl->timer.function = clnp_frag_expires;
		add_timer(&cfl->timer);
		return cfl;
	} else {
		clnp_discard(skb, GEN_INCOMPLETE);
	}

	return NULL;
}

void clnp_insert_frag(struct clnp_fragl *cfl, struct sk_buff *skb
						     , struct clnp_segment *seg)
{
	struct clnp_frag *cf_pre = NULL;
	struct clnp_frag *cf = NULL;
	struct clnp_frag *cf_post = NULL;
	unsigned short first = 0;
	unsigned short last = 0;
	unsigned short fraglen = 0;
	unsigned short hdrlen = 0;
	unsigned short start = 0;
	unsigned short overlap = 0;
	struct clnphdr *clnph = clnp_hdr(skb);

	printk(KERN_INFO "Entering clnp_insert_frag()\n");

	first = ntohs(seg->off);
	fraglen = ntohs(clnph->seglen) - clnph->hdrlen;
	last = first + fraglen - 1;

	/* if it is not the last fragment and the fragment is not modulus 8,
					 we shave the fragment into modulus 8 */
	if (clnph->flag & MS_MASK) {
		if ((last + 1) % 8 != 0) {
			printk(KERN_INFO "The fragment is not modulus 8\n");
			printk(KERN_INFO "Before the fragment is shaved, last"
						 " offset is %d\n", (int) last);
			last = (((last + 1) / 8) * 8) - 1;
			printk(KERN_INFO "After the fragment is shaved, last"
						 " offset is %d\n", (int) last);
		}
	}

	BUG_ON(!cfl->cfl_frags);

	cf = cfl->cfl_frags;
	while (cf != NULL) {
		if (cf->first >= first) {
			cf_post = cf;
			break;
		}
		cf_pre = cf;
		cf = cf->next;
	}

	if (cf_pre != NULL) {
		if (cf_pre->last >= first) {
			overlap = cf_pre->last - first + 1;
			printk(KERN_INFO "Fraglen: %d\n", fraglen);
			if (overlap >= fraglen) {
				printk(KERN_INFO "All part of the new"
						" received segment is included"
						" in the previous adjacent"
								" segment\n");
				kfree_skb(skb);
				return;
			} else {
				printk(KERN_INFO "Only partial part of"
						" the new received segment"
						" overlaps with the previous"
							" adjacent segment\n");
				printk(KERN_INFO "Overlap with previous"
					" fragment: %d bytes\n",overlap);
				first += overlap;
			}
		}
	}

	for (cf = cf_post; cf != NULL; cf = cf->next) {
		if (cf->first <= last) {
			unsigned short overlap = last - cf->first
									+ 1;
			printk(KERN_INFO "Fraglen: %d\n", fraglen);
			if (overlap >= fraglen) {
				printk(KERN_INFO "All part of the new"
						" received segment is included"
							" in the next adjacent"
								" segment\n");
				kfree_skb(skb);
				return;
			} else {
				printk(KERN_INFO "Only partial part of"
						" the new received segment"
						" overlaps with the next"
							" adjacent segment\n");
				printk(KERN_INFO "Overlap with next"
					" fragment: %d bytes\n", overlap);
				last -= overlap;
			}
		}
	}

	/* Insert the new fragment between cf_pre & cf_post */
	cf = (struct clnp_frag *) kmalloc(sizeof(struct clnp_frag), GFP_KERNEL);
	hdrlen = (unsigned short) clnph->hdrlen;
	cf->data = (unsigned char *) kmalloc(sizeof(unsigned char)
					      * (last - first + 1), GFP_KERNEL);
	start = hdrlen + overlap;
	memcpy(cf->data, clnph + start, last - first + 1);

	cf->first = first;
	cf->last = last;
	if (last > cfl->last) {
		cfl->last = last;
	}
	cf->next = cf_post;
	if (cf_pre == NULL) {
		cfl->cfl_frags = cf;
	} else {
		cf_pre->next = cf;
	}
}

struct sk_buff *clnp_comp_frag(struct clnp_fragl *cfh, unsigned short totlen)
{
	struct clnphdr *orihdr_clnph = clnp_hdr(cfh->cfl_orihdr);
	unsigned short hdrlen = orihdr_clnph->hdrlen;
	struct sk_buff *complete_skb = NULL;
	struct clnphdr *complete_clnph = NULL;
	struct clnp_frag *cf = cfh->cfl_frags;
	int start_offset = cf->first;
	int last_offset = 0;

	/* Still under construction by Tadeus Prastowo:
	complete_skb = alloc_skb(totlen + headroom_size(), GFP_ATOMIC);
	skb_reserve(complete_skb, headroom_size());
			 |
			 +--> dev->hard_header_len + datalink->header_len
			      |
			      +--> need to get the device first (routing?)
	complete_clnph = (struct clnph *) skb_put(totlen);
	*/

	memcpy(complete_skb->data, orihdr_clnph, hdrlen);
	complete_skb->data += hdrlen;

	complete_clnph->seglen = htons(hdrlen);

	while (cf != NULL) {
		struct clnp_frag *cf_next = cf->next;

		if (cf_next == NULL) {
			if (cf->first == (last_offset + 1)) {
				last_offset = cf->last;
				concatenate(complete_skb, cf);
			}
		} else {
			if ((cf->last == (cf_next->first - 1))
							  && (cf_next!= NULL)) {
				last_offset = cf->last;
				concatenate(complete_skb, cf);
			}
		}
		cf = cf->next;
	}

	if ((start_offset == 0) && (last_offset == cfh->last)) {
		cfh->complete = 1; /* set complete indicator to true */
		printk(KERN_INFO "All fragments have been received\n");
		printk(KERN_INFO "The complete reassembled data:\n");
		print_data_hex(complete_skb);
		del_timer_sync(&cfh->timer);
		clnp_frag_destroy(cfh);
		return complete_skb;
	}

	printk(KERN_INFO "Fragments are not complete\n");
	kfree(complete_clnph);
	kfree_skb(complete_skb);
	return NULL;
}

struct sk_buff *clnp_defrag(struct sk_buff *skb)
{
	struct clnp_fragl *cfh = NULL;

	if (list_empty(clnp_frags)) {
		cfh = clnp_new_pkt(skb);
	} else {
		cfh = clnp_find(skb);
		if (cnf == NULL) {
			cfh = clnp_new_pkt(skb);
		}
	}

	if (cfh) {
		clnp_insert_frag(cfh, skb);
		if (clnp_fragl_complete(cfh)) {
			return clnp_comp_frag(cfh);
		}
	}

	return NULL;
}
