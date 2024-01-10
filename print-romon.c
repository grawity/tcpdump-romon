#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

/* XXX: preliminary names */
#define PKT_DISCOVER 0x0001
#define PKT_DISCREPLY 0x0002
#define PKT_TRANSPORT 0x0003

static const struct tok subtype_str[] = {
	{ PKT_DISCOVER, "Discover" },
	{ PKT_DISCREPLY, "Discover reply" },
	{ PKT_TRANSPORT, "Transport" },
	{ 0, NULL },
};

#define TLV_ROUTING 0x01
#define TLV_IDENTITY 0x03
#define TLV_VERSION 0x04
#define TLV_HARDWARE 0x05

static const struct tok tag_str[] = {
	{ TLV_ROUTING, "Routing", },
	{ TLV_IDENTITY, "Identity", },
	{ TLV_VERSION, "Version", },
	{ TLV_HARDWARE, "Hardware", },
	{ 0, NULL, },
};

static void
romon_discover_print(netdissect_options *ndo, const u_char *cp, u_int len)
{
	uint8_t num_hops;
	uint8_t hop_ptr;
	int i;

	num_hops = GET_U_1(cp);
	cp += 1; len -= 1;
	hop_ptr = GET_U_1(cp);
	cp += 1; len -= 1;
	ND_PRINT("\n\tHops: %u/%u", hop_ptr, num_hops);

	/* XXX: probably-reserved field ([6] in discover, [4] in transport) */
	cp += 6; len -= 6;

	for (i = 0; i < num_hops; i++) {
		ND_PRINT("\n\tHop %d:", i+1);

		ND_PRINT(" link %lu", GET_BE_U_4(cp));
		cp += 4; len -= 4;

		ND_PRINT(" at %s", GET_MAC48_STRING(cp));
		cp += MAC48_LEN; len -= MAC48_LEN;

		if (i+1 == hop_ptr)
			ND_PRINT(" <--");
	}

	while (len > 0) {
		uint8_t tag;
		uint8_t tlen;

		tag = GET_U_1(cp);
		cp += 1; len -= 1;
		ND_PRINT("\n\tTag: %s (%d)",
			tok2str(tag_str, "Unknown", tag),
			tag);

		tlen = GET_U_1(cp);
		cp += 1; len -= 1;
		ND_PRINT(", length %u", tlen);

		switch (tag) {
		case TLV_ROUTING:
			ND_PRINT(": Router ID %s", GET_MAC48_STRING(cp));
			cp += MAC48_LEN; len -= MAC48_LEN; tlen -= MAC48_LEN;
			while (tlen > 0) {
				ND_PRINT("\n\t\t- foo %lu", GET_BE_U_4(cp));
				cp += 4; len -= 4; tlen -= 4;

				ND_PRINT(", bar %u", GET_BE_U_2(cp));
				cp += 2; len -= 2; tlen -= 2;

				ND_PRINT(", cost %u", GET_BE_U_2(cp));
				cp += 2; len -= 2; tlen -= 2;

				ND_PRINT(", MAC %s", GET_MAC48_STRING(cp));
				cp += MAC48_LEN; len -= MAC48_LEN; tlen -= MAC48_LEN;
			}
			break;
		case TLV_IDENTITY:
		case TLV_HARDWARE:
			ND_TCHECK_LEN(cp, tlen);
			ND_PRINT(": %.*s", tlen, cp);
			cp += tlen; len -= tlen;
			break;
		default:
			ND_PRINT(": unknown");
			cp += tlen; len -= tlen;
		}
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void
romon_transport_print(netdissect_options *ndo, const u_char *cp, u_int len)
{
	uint8_t num_hops;
	uint8_t hop_ptr;
	int i;

	num_hops = GET_U_1(cp);
	cp += 1; len -= 1;
	hop_ptr = GET_U_1(cp);
	cp += 1; len -= 1;
	ND_PRINT("\n\tHops: %u/%u", hop_ptr, num_hops);

	/* XXX: probably-reserved field ([6] in discover, [4] in transport) */
	ND_TCHECK_LEN(cp, 4);
	cp += 4; len -= 4;

	for (i = 0; i < num_hops; i++) {
		ND_PRINT("\n\tHop %d:", i+1);

		ND_PRINT(" link %lu", GET_BE_U_4(cp));
		cp += 4; len -= 4;

		ND_PRINT(" %s", GET_MAC48_STRING(cp));
		cp += MAC48_LEN; len -= MAC48_LEN;

		if (i+1 == hop_ptr)
			ND_PRINT(" <--");
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

void
romon_print(netdissect_options *ndo, const u_char *cp, u_int len)
{
	uint16_t subtype;
	uint16_t framelen;

	ndo->ndo_protocol = "romon";

	/* XXX: This might be u8 subtype + u8 reserved */
	subtype = GET_LE_U_2(cp);
	cp += 2; len -= 2;
	ND_PRINT("\n\tType: %s (0x%04x)",
		tok2str(subtype_str, "Unknown", subtype),
		subtype);

	framelen = GET_BE_U_2(cp);
	cp += 2; len -= 2;
	ND_PRINT(", frame length: %u", framelen);

	/* XXX: Probably a field for HMAC */
	ND_TCHECK_LEN(cp, 24);
	cp += 24; len -= 24;

	ND_PRINT("\n\tSource RoMON ID: %s", GET_MAC48_STRING(cp));
	cp += MAC48_LEN; len -= MAC48_LEN;

	ND_PRINT("\n\tTarget RoMON ID: %s", GET_MAC48_STRING(cp));
	cp += MAC48_LEN; len -= MAC48_LEN;

	switch (subtype) {
	case PKT_DISCOVER:
	case PKT_DISCREPLY:
		romon_discover_print(ndo, cp, len);
		break;
	case PKT_TRANSPORT:
		romon_transport_print(ndo, cp, len);
		break;
	default:
		ND_DEFAULTPRINT(cp, len);
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}
