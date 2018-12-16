/*
 * ATN		CLNP checksum module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	- 2007/09/18:
 *				* Finished debugging clnp_check_csum()
 *		Tadeus:		- 2008/03/30:
 *				* Fixing memory leak in clnp_check_csum()
 *				because temp was never freed as a result of
 *				using return statement in each conditional
 *				branch (the introduction of rc variable settles
 *				this)
 *				* Remove the existence of
 *				`if (x == 0 && y == 0)' do nothing conditional
 *				branch by replacing it with
 *				`if (x != 0 && y != 0)' conditional branch in
 *				function clnp_adjust_csum()
 *				- 2008/04/13:
 *				* Replace all instances of `nh' that is used to
 *				get the CLNP header part with clnp_hdr()
 *				- 2008/04/14:
 *				* Remove from clnp_gen_csum() and
 *				clnp_check_csum() the use of
 *				temp = (unsigned char *) kmalloc(
 *				sizeof(unsigned char) * hdr_len, GFP_KERNEL);
 *				because those two functions are read-only
 *				(this also fixes the memory leak problems as a
 *				result of forgetting to freed temp)
 *				* Remove from clnp_adjust_csum() the use of
 *				int idx_msb and int idx_lsb because they are
 *				redundant
 *				- 2008/05/29:
 *				* Change the parameters of clnp_gen_csum(),
 *				clnp_check_csum(), and clnp_adjust_csum() from
 *				struct sk_buff *skb to struct clnphdr *clnph to
 *				make it clear that those functions are only
 *				dealing with a CLNP header
 *				* Remove the capability of generating an ER PDU
 *				from clnp_adjust_csum() because only the caller
 *				knows the best (e.g., the context: in interrupt
 *				or not)
 *				- 2008/05/30:
 *				* Fix the semantic of clnp_check_csum()
 *				* Add clnp_check_csum_field()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/stddef.h>
#include <net/clnp.h>

/* Private Function Prototypes */
static int clnp_check_csum_field(struct clnphdr *clnph);

void clnp_gen_csum(struct clnphdr *clnph)
{
	int c0 = 0;
	int c1 = 0;
	int x = 0;
	int y = 0;
	int hdr_idx = 0;
	int hdr_len = clnph->hdrlen;
	__u8 *ptr = (__u8 *) clnph;

	clnph->cksum_msb = clnph->cksum_lsb = 0;
	c0 = 0;
	c1 = 0;

	for (hdr_idx = 0; hdr_idx < hdr_len; hdr_idx++) {
		c0 += ptr[hdr_idx];
		c1 += c0;
	}

	x = ((hdr_len - 8) * c0 - c1) % 255;
	if (x < 0) {
		x += 255;
	}

	y = ((hdr_len - 7) * (-c0) + c1) % 255;
	if (y < 0) {
		y += 255;
	}

	if (x == 0) {
		x = 255;
	}
	if (y == 0) {
		y = 255;
	}

	clnph->cksum_msb = x;
	clnph->cksum_lsb = y;
}

/*
 * clnp_check_csum_field() only checks whether or not the checksum field of a
 * CLNP header is valid or not. It does _not_ check for the integrity of the
 * whole CLNP header. To do so, use clnp_check_csum().
 */
static int clnp_check_csum_field(struct clnphdr *clnph)
{
	int c0 = 0;
	int c1 = 0;
	int x = 0;
	int y = 0;
	int hdr_idx = 0;
	int hdr_len = clnph->hdrlen;
	int rc = 0;
	__u8 *ptr = (__u8 *) clnph;
	__u8 cksum_msb = clnph->cksum_msb;
	__u8 cksum_lsb = clnph->cksum_lsb;

	if ((cksum_lsb == 0) && (cksum_msb == 0)) {
		rc = 0;
	} else if ((cksum_lsb == 0) && (cksum_msb != 0)) {
		rc = -GEN_BADCSUM;
	} else if ((cksum_lsb != 0) && (cksum_msb == 0)) {
		rc = -GEN_BADCSUM;
	} else {
		c0 = c1 = 0;
		x = y = 0;
		for (hdr_idx = 0; hdr_idx < hdr_len; hdr_idx++) {
			c0 = (c0 + ptr[hdr_idx]);
			c1 = (c1 + c0);
		}

		x = c0 % 255;
		y = c1 % 255;

		if (x || y) {
			rc = -GEN_BADCSUM;
		} else {
			rc = 0;
		}
	}

	return rc;
}

int clnp_check_csum(struct clnphdr *clnph)
{
	__u8 cksum_msb = 0;
	__u8 cksum_lsb = 0;

	if (clnp_check_csum_field(clnph)) {
		return -GEN_BADCSUM;
	}

	cksum_msb = clnph->cksum_msb;
	cksum_lsb = clnph->cksum_lsb;
	clnp_gen_csum(clnph);

	if (cksum_msb != clnph->cksum_msb || cksum_lsb != clnph->cksum_lsb) {
		clnph->cksum_msb = cksum_msb;
		clnph->cksum_lsb = cksum_lsb;
		return -GEN_BADCSUM;
	}

	return 0;
}

int clnp_adjust_csum(struct clnphdr *clnph, int idx_changed, __u8 new_value
							       , __u8 old_value)
{
	int z = new_value - old_value;
	int x = clnph->cksum_msb;
	int y = clnph->cksum_lsb;
	int idx_cksum_msb = offsetof(struct clnphdr, cksum_msb);

	/*
	 * If both checksum values equal zero, do nothing.
	 * If either checksum value equals zero, checksum is incorrect.
	 * Else, calculate the new value of x and y
	 */
	if (x != 0 && y != 0) {
		x = ((idx_changed - idx_cksum_msb - 1) * z + x) % 255;
		if (x < 0) {
			x += 255;
		}

		y = ((idx_cksum_msb - idx_changed) * z + y) % 255;
		if (y < 0) {
			y += 255;
		}

		if (x == 0) {
			x = 255;
		}
		if (y == 0) {
			y = 255;
		}

		clnph->cksum_msb = x;
		clnph->cksum_lsb = y;
	} else if ((x == 0 && y != 0) || (x != 0 && y == 0)) {
		return -GEN_BADCSUM;
	}

	return 0;
}
