/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Pradana Atmadiputra <pradana.priyono@student.sgu.ac.id>
 * 		Melvin Rubianto <melvin.rubianto@student.sgu.ac.id>
 * 		Danny Laidi <danny.laidi@student.sgu.ac.id>
 * 		Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Pradana:	* Define clnp_fixed, clnp_segment, and
 *				clnp_address structure
 *  		Melvin:		* Define parameter type and parameter value for
 *				the option part of CLNP
 *		Danny:		* Define the extra variables (FIXED_LEN,
 *				ADDR_LEN, SEG_LEN, etc.)
 *		Danny:		* Define general constant variable in header
 *				fixed part (CLNPVERSION, NLPID, MAXTTL)
 *		Danny:		* Define mask for CLNP Flag Fields
 *		Danny:		* Define CLNP packet types
 * 		Danny:		* Define CLNP option structure
 *    		Bunga:		* Define CLNP error codes
 *		Bunga:		* Define CLNP header structure
 *		Bunga:		* Add big and little endian condition inside
 *				clnp_fixed
 *		Tadeus:		- 2008/03/27:
 *				* Clean up the code and notice that:
 *				- clnp_fixed and clnp_address structures have
 *				  been combined into clnphdr structure
 *				- FIXED_LEN has gone
 *				* Move in clnp_fragl and clnp_frag from
 *				clnp_fragment.c to make all data structures
 *				available in one place
 *				- 2008/03/30:
 *				* Change the way each field in a struct is
 *				commented; from comments inside the struct to
 *				comments before the struct to follow Linux
 *				coding style guideline (kernel-doc nano-HOWTO)
 *				- 2008/04/06:
 *				* Change ER_MASKR_OK to ER_MASK, CNF_MORE_SEGS to
 *				MS_MASK, and CNF_SEG_OK to SP_MASK for better mask
 *				names
 *				- 2008/04/14:
 *				* Replace `#define IDX_SEGLEN_MSB 5' and
 *				`#define IDX_SEGLEN_LSB 6' with
 *				`#define IDX_SEGLEN 5' to harness htons() and
 *				ntohs() eliminating the clutter in using
 *				#if defined(__BIG_ENDIAN_BITFIELD)
 *				...
 *				#elif defined(__LITTLE_ENDIAN_BITFIELD)
 *				...
 *				#else
 *				...
 *				#endif
 *				* Make it clear in the corresponding kernel-doc
 *				that seglen of struct clnphdr along with
 *				id, off, and tot_len of
 *				struct clnp_segment are in network byte order
 *				* Add __attribute__ ((packed)) to struct clnphdr
 *				because its size (51 bytes) causes difficulty in
 *				retrieving seglen with clnp_hdr() as a
 *				result of memory alignment
 *				- 2008/04/17:
 *				* Add next_part to `struct clnphdr' so that the
 *				following part of a CLNP header can be accessed
 *				elegantly
 *				* Replace `unsigned char *value' in
 *				`struct clnp_options' with `__u8 value[0]'
 *				because the data that value should point to
 *				is always located contiguously with the data of
 *				code and len (this saves the memory
 *				space used up by the pointer)
 *				- 2008/04/18:
 *				* Replace NLPID with CLNP_NLPID to avoid
 *				conflict in the future with NLPID of IS-IS and
 *				ES-IS PDU
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_CLNP_H
#define _LINUX_CLNP_H

#include <asm/types.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/types.h>

/*
 * Various values for the fixed part of a CLNP header
 */
#define CLNP_VERSION	1	/* CLNP version */
#define CLNP_NLPID	0x81	/* CLNP network layer protocol ID */
#define INAC_NLPID	0x00	/* inactive network layer protocol ID */
#define CLNP_MAXTTL	255	/* maximum time-to-live */
#define CLNP_TTL_UNITS	2	/* 500 miliseconds */
#define CLNP_FIX_LEN	51	/* the minimum length of a CLNP header */
#define CLNP_HDR_MAX	254	/* the maximum length of a CLNP header */
#define NSAP_ADDR_LEN	20	/* the length of the address value */

/*
 * Various values for the segmentation part of a CLNP header
 */
#define SEG_LEN 6		/* the total length of a segmentation part */

/*
 * Reassembly variables
 */
#define CLNP_FRAG_TIME (30 * HZ)	/* fragment lifetime */

/*
 * Mask for CLNP Flag field
 */
#define TYPE_MASK 0x1F
#define ER_MASK 0x20
#define MS_MASK 0x40
#define SP_MASK 0x80

/*
 * CLNP packet types: this is defined from the last 5 bits in the Flag field
 * inside a CLNP header
 */
#define CLNP_DT 0x1C	/* Data Protocol Data Unit: normal data */
#define CLNP_MD 0x1D	/* Multicast Data PDU */
#define CLNP_ER 0x01	/* Error Report PDU */
#define CLNP_ERQ 0x1E	/* Echo Request PDU */
#define CLNP_ERP 0x1F	/* Echo Reply PDU */

/*
 * Field values of ATN NSAP (Network Service Access Point) address format
 * Read the comment as (field name: semantic of the value)
 */
#define AFI 0x2F		/* authority and format identifier: ISO 6523 ICD
				 * IDI and binary DSP format
				 */
#define IDI_1 0x00		/* 1st byte initial domain identifier:
#define IDI_2 0x1B		 * 2nd byte initial domain identifier:
				 *				ATN NSAP address
				 */
#define VER_G_AINSC 0x01	/* version:	ground AINSC NSAP address
#define VER_M_AINSC 0x41	 * 		mobile AINSC NSAP address
#define VER_G_ATSC 0x81		 * 		ground ATSC NSAP address
#define VER_M_ATSC 0xC1		 * 		mobile ATSC NSAP address
				 */
#define RDF 0x00		/* routing domain format: unassigned */

/*
 * Options part of a CLNP header
 */

/* Various parameters in the options part */
#define CLNP_OPTIONS 8			/* the number of parameter codes */

#define CLNPOPT_PC_PAD 0xCC		/* padding */
#define CLNPOPT_PC_SEC 0xC5		/* security */
#define CLNPOPT_PC_SRCROUTE 0xC8	/* source routing */
#define CLNPOPT_PC_ROR 0xCB		/* recording of route */
#define CLNPOPT_PC_QOS 0xC3		/* quality of service */
#define CLNPOPT_PC_PRIOR 0xCD		/* priority */
#define CLNPOPT_PC_PBSC 0xC4		/* prefix based scope control */
#define CLNPOPT_PC_RSC 0xC6		/* radius scope control */

/* Parameter value for Security Option -- if code equals to 0xC5 */
#define SEC_RESERVED 0x00		/* reserved */
#define SEC_SRCADDRSPECIFIC 0x40	/* source address specific */
#define SEC_DESADDRSPECIFIC 0x80	/* destination address specific */
#define SEC_GLOBALUNIQUE 0xC0		/* globally unique */

/* Parameter value for Priority Option -- if code equals to 0xCD */
#define PRIOR_NORMAL 0x00		/* normal (default) relative priority */
/* ... other relative priority values can be specified between these ... */
#define PRIOR_HIGHEST 0x0E		/* the highest relative priority */

/* Parameter value for Source Routing Option -- if code equals to 0xC8 */
#define SRCROUTE_RESERVED 0x00		/* reserved */
#define SRCROUTE_COMPLETESRCROUTE 0x01	/* complete source routing */
#define SRCROUTE_PARTIALSRCROUTE 0x02	/* partial source routing */

/* Parameter value for Recording of Route Option -- if code equals to 0xCB
 */
#define ROR_PARTIAL 0x00 	/* partial recording of route in progress */
#define ROR_COMPLETE 0x01	/* complete recording of route in progress */
#define ROR_PARTIAL_TS 0x02	/* partial recording of route in progress
				 * (with timestamps)
				 */
#define ROR_COMPLETE_TS	0x03	/* complete recording of route in progress
				 * (with timestamps)
				 */

/* Parameter value for QoS maintenance -- if code equals to 0xC3 */
#define QOS_GLOBAL 0x00			/* globally unique with strong
					 * forwarding
					 */
#define QOS_SRCADDRSPECIFIC 0x40	/* source address specific */
#define QOS_DESADDRSPECIFIC 0x80	/* destination address specific */
#define QOS_GLOBALUNIQUEWEAK 0xC0	/* globally unique with weak forwarding
					 */

/*
 * PDU error codes
 */

/* Parameter code for `Reason for Discard' */
#define REASON_DISCARD 0xC1	/* reason for discard */
#define REASON_LEN 4		/* the length of the reason for discard */
#define CLNP_ERRORS 24		/* the total number of error codes below */

/* General errors */
#define GEN_NOREAS 0x00		/* reason not specified */
#define GEN_PROTOERR 0x01	/* protocol procedure error */
#define GEN_BADCSUM 0x02	/* incorrect checksum */
#define GEN_CONGEST 0x03	/* PDU discarded due to congestion */
#define GEN_HDRSYNTAX 0x04	/* header syntax error */
#define GEN_SEGNEEDED 0x05	/* need segmentation but not allowed */
#define GEN_INCOMPLETE 0x06	/* incomplete PDU received */
#define GEN_DUPOPT 0x07		/* duplicate option */
#define GEN_UNKNOWN 0x08	/* unknown PDU Type */

/* Address errors */
#define ADDR_DESTUNREACH 0x80	/* destination address unreachable */
#define ADDR_DESTUNKNOWN 0x81	/* destination address unknown */

/* Source routing errors */
#define SRCRT_UNSPECERR	0x90	/* unspecified source routing error */
#define SRCRT_SYNTAX 0x91	/* syntax error in source routing field */
#define SRCRT_UNKNOWNADDR 0x92	/* unknown address in source routing field */
#define SRCRT_BADPATH 0x93	/* path not acceptable */

/* Lifetime errors */
#define TTL_EXPTRANSIT 0xA0	/* lifetime expired while PDU in transit */
#define TTL_EXPREASS 0xA1	/* lifetime expired during reassembly */

/* PDU discarded because of */
#define DISC_UNSUPPOPT 0xB0	/* unsupported option not specified */
#define DISC_UNSUPPVERS 0xB1	/* unsupported protocol version */
#define DISC_UNSUPPSECURE 0xB2	/* unsupported security option */
#define DISC_UNSUPPSRCRT 0xB3	/* unsupported source routing option */
#define DISC_UNSUPPRECRT 0xB4	/* unsupported recording of route option */
#define DISC_UNAVAILQOS	 0xB5	/* unsupported or unavailable QoS */

/* Reassembly errors */
#define REASS_INTERFERE 0xC0	/* reassembly interference */

/**
 * struct clnphdr - CLNP header
 * @nlpid: network layer protocol identifier
 * @hdrlen: header length (length of fixed + segmentation + options part)
 * @vers: version/protocol ID extension
 * @ttl: lifetime
 * @flag: SP, MS, E/R, PDU type
 * @seglen: segment length in network byte order
 * @cksum_msb: checksum - most significant byte
 * @cksum_lsb: checksum - least significant byte
 * @dest_len: destination address length indicator
 * @dest_addr: destination address
 * @src_len: source address length indicator
 * @src_addr: source address
 * @next_part: either the optional segmentation part, the optional options part,
 *             or the payload
 */
struct clnphdr {
	__u8 nlpid;
	__u8 hdrlen;
	__u8 vers;
	__u8 ttl;
	__u8 flag;
	__be16 seglen;
	__u8 cksum_msb;
	__u8 cksum_lsb;
	__u8 dest_len;
	__u8 dest_addr[NSAP_ADDR_LEN];
	__u8 src_len;
	__u8 src_addr[NSAP_ADDR_LEN];
	__u8 next_part[0];
} __attribute__ ((packed));

/**
 * struct clnp_segment
 * @id: data unit identifier in network byte order
 * @off: segment offset in network byte order
 * @tot_len: total length in network byte order
 * @next_part: either the optional options part or the payload
 */
struct clnp_segment {
	__be16 id;
	__be16 off;
	__be16 tot_len;
	__u8 next_part[0];
};

/**
 * struct clnp_options - describes a parameter in the options part of a CLNP hdr
 * @code: parameter code
 * @len: parameter length
 * @value: parameter value
 */
struct clnp_options {
	__u8 code;
	__u8 len;
	__u8 value[0];
};

/**
 * struct clnp_fragment_list - CLNP fragment reassembly structure
 * @list: pointer to next packet being reassembled
 * @id: data unit identifier
 * @dstaddr: destination address of the packet
 * @srcaddr: source address of the packet
 * @curlen: indicator if the fragl is complete
 * @totlen: pointer to the original header of the packet
 * @status:
 * @fragments: linked list of fragments for packet
 * @timer: reassembly timer for this list
 *
 * All packets being reassembled are linked together as a linked list of
 * clnp_fragment_list structure. Each clnp_fragment_list structure contains a
 * pointer a linked-list of sk_buff structure containing the fragments that make
 * up the packet that the clnp_fragment_list structure represents.
 */
struct clnp_fragment_list {
	struct hlist_node list;
	__u16 id;
	__u8 dest_addr[NSAP_ADDR_LEN];
	__u8 src_addr[NSAP_ADDR_LEN];
	__u16 curlen;
	__u16 totlen;
	__u8 status;
#define COMPLETE	4
#define FIRST_IN	2
#define LAST_IN		1

	struct sk_buff *fragments;
	struct timer_list timer;
};

#endif /* _LINUX_CLNP_H */
