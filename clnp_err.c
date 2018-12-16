/*
 * ATN		CLNP error module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		- 2008/04/01:
 *				* Fix a memory leak in clnp_emit_er() because
 *				our_addr, skb_err->data, and skb_err were not
 *				freed
 *				- 2008/04/06:
 *				* Replace all invocation of masking() with
 *				(& CNF_*)
 *				- 2008/04/13:
 *				* Replace all instances of `nh' that is used to
 *				get the CLNP header part with clnp_hdr()
 *				- 2008/04/14:
 *				* Replace skb_err = (struct sk_buff *) kmalloc(
 *				sizeof(struct sk_buff), GFP_KERNEL) in
 *				clnp_emit_er() with skb_err = alloc_skb()
 *				because `struct sk_buff' must always be created
 *				with alloc_skb() or its wrapper functions
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
 *				- 2008/04/15:
 *				* Make clnp_emit_er() more elegant by harnessing
 *				the introduction of next_part to
 *				`struct clnphdr' and the alteration of value
 *				in `struct clnp_options'
 *				- 2008/04/19:
 *				* Complete restructuring of clnp_emit_er() sans
 *				altering its logic
 *				- 2008/??/??:
 *				* Finish a major overhaul of clnp_discard() and
 *				clnp_emit_er()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/byteorder/generic.h>
#include <linux/clnp.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/clnp.h>

/* Private Function Prototypes */
static void clnp_emit_er(struct sk_buff *skb, __u8 reason, __u8 location
							      , gfp_t gfp_mask);

/*
 * clnp_discard() shall only perform sanity check on @skb to decide whether to
 * actually send back an error report PDU by invoking clnp_emit_er() or not
 */
int clnp_discard(struct sk_buff *skb, __u8 reason, __u8 location
							       , gfp_t gfp_mask)
{
	struct clnphdr *clnph = NULL;

	skb = skb_clone(skb, gfp_mask);
	clnph = clnp_hdr(skb);

	if ((clnph->flag & TYPE_MASK != CLNP_ER) && (clnph->flag & ER_MASK)) {
		return clnp_emit_er(skb, reason, location, gfp_mask);
	} else {
		kfree_skb(skb);
	}

	return 0;
}

static int clnp_emit_er (struct sk_buff *skb, __u8 reason, __u8 location
							       , gfp_t gfp_mask)
{
	struct net_device *dev_out = skb->dev;

	struct clnphdr *clnph = NULL;
	__u8 clnph_hdrlen = 0;
	__u8 *clnph_opt = 0;
	__u8 clnph_opt_len = 0;

	struct sk_buff *err = NULL;
	struct clnphdr *err_clnph = NULL;
	__u8 err_hdrlen = 0;
	__u16 err_seglen = 0;
	struct clnp_options *reason_for_discard = NULL;

	if (!dev_out) {
		kfree_skb(skb);
		return -ENODEV;
	}

	clnph = clnp_hdr(skb);
	clnph_hdrlen = clnph->hdrlen > skb->len ? skb->len : clnph->hdrlen;
	clnph_opt = clnph->next_part;

	/* how long is the options part of clnph? */
	if (clnph_hdrlen > CLNP_FIX_LEN) {
		if (clnph->flag & SP_MASK) {
			if (clnph_hdrlen > (CLNP_FIX_LEN + SEG_LEN)) {
				clnph_opt += SEG_LEN;
				clnph_opt_len = clnph_hdrlen - CLNP_FIX_LEN
								      - SEG_LEN;
			}
		} else {
			clnph_opt_len = clnph_hdrlen - CLNP_FIX_LEN;
		}
	}

	/* instantiating the CLNP ER PDU */
	err_hdrlen = CLNP_FIX_LEN + clnph_opt_len + REASON_LEN;
	err_seglen = err_hdrlen + clnph_hdrlen;

	err = alloc_skb(atn_skb_headroom + err_seglen, gfp_mask);

	/* loading the CLNP ER payload */
	skb_reserve(err, atn_skb_headroom(dev_out) + err_hdrlen);
	memcpy(skb_put(skb, clnph_hdrlen), clnph, clnph_hdrlen);

	/* loading the CLNP ER header */
	err_clnph = (struct clnphdr *) skb_push(err, err_hdrlen);

	err_clnph->nlpid = CLNP_NLPID;
	err_clnph->hdrlen = err_hdrlen;
	err_clnph->vers = CLNP_VERSION;
	err_clnph->ttl = CLNP_TTL_UNITS;
	err_clnph->flag = set_flag(0, 0, 0, CLNP_ER);
	err_clnph->seglen = htons(err_seglen);
	err_clnph->cksum_msb = 0;
	err_clnph->cksum_lsb = 0;
	err_clnph->dest_len = clnph->src_len;
	memcpy(err_clnph->dest_addr, clnph->src_addr, clnph->src_len);
	err_clnph->src_len = NSAP_ADDR_LEN;
	/* Woi! */ error get_nsap_addr(err_clnph->src_addr);

	if (clnph_opt_len) {
		memcpy(err_clnph->next_part, clnph_opt, clnph_opt_len);
	}

	reason_for_discard = (struct clnp_options *) (err_clnph->next_part
							       + clnph_opt_len);
	reason_for_discard->code = REASON_DISCARD;
	reason_for_discard->len = 2;
	reason_for_discard->value[0] = reason;
	reason_for_discard->value[1] = location;

	clnp_gen_csum(err, err_clnph->hdrlen);

	/* send the CLNP ER out */
	return atn_xmit(skb);
}
