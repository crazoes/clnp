/*
 * clnp_util.c	Functions that are used together inside CLNP module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	- 2007/08/21:
 *				* Declare utility functions for CLNP packet
 *				processing
 *		Husni Fahmi:	- 2007/08/28:
 *				* Finished debugging clnp_decompose() and
 *				print_header_clnp()
 *		Tadeus:		- 2008/04/06:
 *				* Remove masking() because it causes too much
 *				overhead (the programmer should have used the
 *				bitwise operator `&' as well as `if (flag)' or
 *				`if (!flag)' to test whether or not the flag is
 *				set)
 *				* Remove power() because it is unused
 *				* Optimize set_flag()
 *				* Revise print_data_hex() to produce a neat
 *				output
 *				- 2008/04/13:
 *				* Add clnp_hdr() and replace all instances of
 *				`nh' that is used to get the CLNP header part
 *				so that it is more maintainable when the CLNP
 *				header is pointed by `h' instead of `nh' as
 *				a result of LLC header processing
 *				- 2008/04/14:
 *				* Replace clnph->seglen with
 *				ntohs(clnph->seglen) because a corresponding
 *				modification in include/linux/clnp.h states that
 *				clnph->seglen is in network byte order
 *				* Remove clnp_decompose(skb, clnph) and
 *				free_mem_alloc() for a reason stated in
 *				clnp_input.c
 *				* Remove merge_chars_to_short() because its sole
 *				use equals to ntohs(clnph->seglen)
 *				* Replace the following construct
 *				#if defined(__BIG_ENDIAN_BITFIELD)
 *				...
 *				#elif defined(__LITTLE_ENDIAN_BITFIELD)
 *				...
 *				#else
 *				...
 *				#endif
 *				with the equivalent ntohs()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/byteorder/generic.h>
#include <linux/clnp.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <net/clnp.h>

void print_header_clnp(struct clnphdr *clnph)
{
	int i = 0;

	printk(KERN_INFO "Printing CLNP header:\n");
	printk(KERN_INFO "Network Layer Protocol ID: 0x%02X\n"
							 , clnph->nlpid);
	printk(KERN_INFO "Header length: %d\n", clnph->hdrlen);
	printk(KERN_INFO "Version: %d\n", clnph->vers);
	printk(KERN_INFO "Time-to-live: %d\n", clnph->ttl);
	printk(KERN_INFO "Flags: SP: %d MS: %d ER: %d PDU type:"
		    , !!(clnph->flag & SP_MASK), !!(clnph->flag & MS_MASK)
		 				, !!(clnph->flag & ER_MASK));
	switch (clnph->flag & TYPE_MASK) {
	case CLNP_DT:
		printk(KERN_INFO "DT PDU (normal data)\n");
		break;
	case CLNP_MD:
		printk(KERN_INFO "MD PDU (multicast data)\n");
		break;
	case CLNP_ER:
		printk(KERN_INFO "ER PDU (error report)\n");
		break;
	case CLNP_ERQ:
		printk(KERN_INFO "ERQ PDU (echo request)\n");
		break;
	case CLNP_ERP:
		printk(KERN_INFO "ERP PDU (echo reply)\n");
		break;
	default:
		printk(KERN_INFO "unknown\n");
	}
	printk(KERN_INFO "Segmentation length: %d\n", ntohs(clnph->seglen));
	printk(KERN_INFO "Checksum MSB: %d\n", clnph->cksum_msb);
	printk(KERN_INFO "Checksum LSB: %d\n", clnph->cksum_lsb);
	printk(KERN_INFO "Destination address length: %d\n", clnph->dest_len);
	printk(KERN_INFO "Destination address: 0x");
	for (i = 0; i < clnph->dest_len; i++) {
		printk(KERN_INFO "%02X%s", clnph->dest_addr[i]
				     , (i + 1 == clnph->dest_len) ? "\n" : " ");
	}
	printk(KERN_INFO "Source address length: %d\n", clnph->src_len);
	printk(KERN_INFO "Source address: 0x");
	for (i = 0; i < clnph->src_len; i++) {
		printk(KERN_INFO "%02X%s", clnph->src_addr[i]
				      , (i + 1 == clnph->src_len) ? "\n" : " ");
	}
}

void print_header_segment(struct clnp_segment *seg)
{
	printk(KERN_INFO "Printing CLNP segmentation part:\n");
	printk(KERN_INFO "Data unit ID: %d\n", ntohs(seg->id));
	printk(KERN_INFO "Segment offset: %d\n", ntohs(seg->off));
	printk(KERN_INFO "Total length: %d\n", ntohs(seg->tot_len));
}

void print_header_options(struct clnp_options *opt)
{
	int i = 0;

	printk(KERN_INFO "Printing an optional part of a CLNP header\n");
	printk(KERN_INFO "Option parameter code: 0x%02X -> ", opt->code);
	switch (opt->code) {
	case CLNPOPT_PC_PAD:
		printk(KERN_INFO "padding\n");
		break;
	case CLNPOPT_PC_SEC:
		printk(KERN_INFO "security\n");
		break;
	case CLNPOPT_PC_SRCROUTE:
		printk(KERN_INFO "source routing\n");
		break;
	case CLNPOPT_PC_ROR:
		printk(KERN_INFO "recording of route\n");
		break;
	case CLNPOPT_PC_QOS:
		printk(KERN_INFO "quality of service\n");
		break;
	case CLNPOPT_PC_PRIOR:
		printk(KERN_INFO "priority\n");
		break;
	case CLNPOPT_PC_PBSC:
		printk(KERN_INFO "prefix based scope control\n");
		break;
	case CLNPOPT_PC_RSC:
		printk(KERN_INFO "radius scope control\n");
		break;
	default:
		printk(KERN_INFO "unknown\n");
	}
	printk(KERN_INFO "Option parameter length: %d\n", opt->len);
	for(i = 0; i < opt->len; i++) {
		printk(KERN_INFO "Option parameter value[%d]: 0x%02X\n", i
							   , opt->value[i]);
	}
}

void print_data_hex(struct sk_buff *skb)
{
	struct clnphdr *clnph = clnp_hdr(skb);
	int len = ntohs(clnph->seglen);
	int i = 0;
	int j = 0;

	printk(KERN_INFO "Printing payload:\n");
	for (i = clnph->hdrlen; i < len; i += 16) {
		for (j = 0; j < 16 && i + j < len; j++) {
			printk(KERN_INFO "%02X%s", clnph[i + j]
							, (j != 15) ? " " : "");
		}
		while (j < 16) {
			printk(KERN_INFO "  %s", (j != 15) ? " " : "");
			++j;
		}
		printk(KERN_INFO ": ");
		for (j = 0; j < 16 && i + j < len; j++) {
			if (isprint (clnph[i + j])) {
				printk(KERN_INFO "%c", clnph[i + j]);
			} else {
				printk(KERN_INFO ".");
			}
		}
		printk(KERN_INFO "\n");
	}
}
