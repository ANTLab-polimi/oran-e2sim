/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "E2SM-KPM-v02.00.03.asn"
 * 	`asn1c -pdu=auto -fno-include-deps -fcompound-names -findirect-choice -gen-PER -gen-OER -no-gen-example -D E2SM-KPM-v02.00.03`
 */

#include "GlobalKPMnode-gNB-ID.h"

asn_TYPE_member_t asn_MBR_GlobalKPMnode_gNB_ID_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GlobalKPMnode_gNB_ID, global_gNB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GlobalgNB_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"global-gNB-ID"
		},
	{ ATF_POINTER, 2, offsetof(struct GlobalKPMnode_gNB_ID, gNB_CU_UP_ID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GNB_CU_UP_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gNB-CU-UP-ID"
		},
	{ ATF_POINTER, 1, offsetof(struct GlobalKPMnode_gNB_ID, gNB_DU_ID),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GNB_DU_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gNB-DU-ID"
		},
};
static const int asn_MAP_GlobalKPMnode_gNB_ID_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_GlobalKPMnode_gNB_ID_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_GlobalKPMnode_gNB_ID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* global-gNB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* gNB-CU-UP-ID */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* gNB-DU-ID */
};
asn_SEQUENCE_specifics_t asn_SPC_GlobalKPMnode_gNB_ID_specs_1 = {
	sizeof(struct GlobalKPMnode_gNB_ID),
	offsetof(struct GlobalKPMnode_gNB_ID, _asn_ctx),
	asn_MAP_GlobalKPMnode_gNB_ID_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_GlobalKPMnode_gNB_ID_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_GlobalKPMnode_gNB_ID = {
	"GlobalKPMnode-gNB-ID",
	"GlobalKPMnode-gNB-ID",
	&asn_OP_SEQUENCE,
	asn_DEF_GlobalKPMnode_gNB_ID_tags_1,
	sizeof(asn_DEF_GlobalKPMnode_gNB_ID_tags_1)
		/sizeof(asn_DEF_GlobalKPMnode_gNB_ID_tags_1[0]), /* 1 */
	asn_DEF_GlobalKPMnode_gNB_ID_tags_1,	/* Same as above */
	sizeof(asn_DEF_GlobalKPMnode_gNB_ID_tags_1)
		/sizeof(asn_DEF_GlobalKPMnode_gNB_ID_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_GlobalKPMnode_gNB_ID_1,
	3,	/* Elements count */
	&asn_SPC_GlobalKPMnode_gNB_ID_specs_1	/* Additional specs */
};
