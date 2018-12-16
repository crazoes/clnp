/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		- 2008/04/07:
 *				* Define struct atn_addr, sockaddr_atn, atn_sock
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_ATN_H_
#define _LINUX_ATN_H_ 1

#include <linux/clnp.h>
#include <linux/if_ether.h>
#include <linux/socket.h>
#include <net/sock.h>

#define ATN_HTABLE_SIZE 256

struct atn_addr {
	__u8 s_addr[NSAP_ADDR_LEN];
};

struct sockaddr_atn {
	sa_family_t	satn_family;
	struct atn_addr	satn_addr;
	unsigned char	satn_mac_addr[ETH_ALEN];
};

struct atn_sock {
	/* struct sock has to be the first member of atn_sock */
	struct sock	sk;
	struct atn_addr nsap;
	unsigned char	snpa[ETH_ALEN];
};

#endif
