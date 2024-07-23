#ifndef BEARSSL_IMPL_SSL_SSL_HS_SERVER_HPP
#define BEARSSL_IMPL_SSL_SSL_HS_SERVER_HPP

/* Automatically generated code; do not modify directly. */

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t *dp;
	uint32_t *rp;
	const unsigned char *ip;
} _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context;

 inline  uint32_t
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_unsigned(const unsigned char **p)
{
	uint32_t x;

	x = 0;
	for (;;) {
		unsigned y;

		y = *(*p) ++;
		x = (x << 7) | (uint32_t)(y & 0x7F);
		if (y < 0x80) {
			return x;
		}
	}
}

 inline  int32_t
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_signed(const unsigned char **p)
{
	int neg;
	uint32_t x;

	neg = ((**p) >> 6) & 1;
	x = (uint32_t)-neg;
	for (;;) {
		unsigned y;

		y = *(*p) ++;
		x = (x << 7) | (uint32_t)(y & 0x7F);
		if (y < 0x80) {
			if (neg) {
				return -(int32_t)~x - 1;
			} else {
				return (int32_t)x;
			}
		}
	}
}

#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, n)   (unsigned char)((((uint32_t)(x) >> (n)) & 0x7F) | 0x80)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_FBYTE(x, n)   (unsigned char)(((uint32_t)(x) >> (n)) & 0x7F)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_SBYTE(x)      (unsigned char)((((uint32_t)(x) >> 28) + 0xF8) ^ 0xF8)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(x)       _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_FBYTE(x, 0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(x)       _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 7), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_FBYTE(x, 0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT3(x)       _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 14), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 7), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_FBYTE(x, 0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT4(x)       _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 21), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 14), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 7), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_FBYTE(x, 0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT5(x)       _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_SBYTE(x), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 21), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 14), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_VBYTE(x, 7), _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_FBYTE(x, 0)

/* static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_datablock[]; */


void br_ssl_hs_server_init_main(void *t0ctx);

void br_ssl_hs_server_run(void *t0ctx);



#include <stddef.h>
#include <string.h>

#include "inner.h"

/*
 * This macro evaluates to a pointer to the current engine context.
 */
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG  ((br_ssl_engine_context *)((unsigned char *)t0ctx - offsetof(br_ssl_engine_context, cpu)))





/*
 * This macro evaluates to a pointer to the server context, under that
 * specific name. It must be noted that since the engine context is the
 * first field of the br_ssl_server_context structure ('eng'), then
 * pointers values of both types are interchangeable, modulo an
 * appropriate cast. This also means that "adresses" computed as offsets
 * within the structure work for both kinds of context.
 */
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX  ((br_ssl_server_context *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG)

/*
 * Decrypt the pre-master secret (RSA key exchange).
 */
 inline  void
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_rsa_decrypt(br_ssl_server_context *ctx, int prf_id,
	unsigned char *epms, size_t len)
{
	uint32_t x;
	unsigned char rpms[48];

	/*
	 * Decrypt the PMS.
	 */
	x = (*ctx->policy_vtable)->do_keyx(ctx->policy_vtable, epms, &len);

	/*
	 * Set the first two bytes to the maximum supported client
	 * protocol version. These bytes are used for version rollback
	 * detection; forceing the two bytes will make the master secret
	 * wrong if the bytes are not correct. This process is
	 * recommended by RFC 5246 (section 7.4.7.1).
	 */
	br_enc16be(epms, ctx->client_max_version);

	/*
	 * Make a random PMS and copy it above the decrypted value if the
	 * decryption failed. Note that we use a constant-time conditional
	 * copy.
	 */
	br_hmac_drbg_generate(&ctx->eng.rng, rpms, sizeof rpms);
	br_ccopy(x ^ 1, epms, rpms, sizeof rpms);

	/*
	 * Compute master secret.
	 */
	br_ssl_engine_compute_master(&ctx->eng, prf_id, epms, 48);

	/*
	 * Clear the pre-master secret from RAM: it is normally a buffer
	 * in the context, hence potentially long-lived.
	 */
	memset(epms, 0, len);
}

/*
 * Common part for ECDH and ECDHE.
 */
 inline  void
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ecdh_common(br_ssl_server_context *ctx, int prf_id,
	unsigned char *xcoor, size_t xcoor_len, uint32_t ctl)
{
	unsigned char rpms[80];

	if (xcoor_len > sizeof rpms) {
		xcoor_len = sizeof rpms;
		ctl = 0;
	}

	/*
	 * Make a random PMS and copy it above the decrypted value if the
	 * decryption failed. Note that we use a constant-time conditional
	 * copy.
	 */
	br_hmac_drbg_generate(&ctx->eng.rng, rpms, xcoor_len);
	br_ccopy(ctl ^ 1, xcoor, rpms, xcoor_len);

	/*
	 * Compute master secret.
	 */
	br_ssl_engine_compute_master(&ctx->eng, prf_id, xcoor, xcoor_len);

	/*
	 * Clear the pre-master secret from RAM: it is normally a buffer
	 * in the context, hence potentially long-lived.
	 */
	memset(xcoor, 0, xcoor_len);
}

/*
 * Do the ECDH key exchange (not ECDHE).
 */
 inline  void
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdh(br_ssl_server_context *ctx, int prf_id,
	unsigned char *cpoint, size_t cpoint_len)
{
	uint32_t x;

	/*
	 * Finalise the key exchange.
	 */
	x = (*ctx->policy_vtable)->do_keyx(ctx->policy_vtable,
		cpoint, &cpoint_len);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ecdh_common(ctx, prf_id, cpoint, cpoint_len, x);
}

/*
 * Do the full static ECDH key exchange. When this function is called,
 * it has already been verified that the cipher suite uses ECDH (not ECDHE),
 * and the client's public key (from its certificate) has type EC and is
 * apt for key exchange.
 */
 inline  void
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_static_ecdh(br_ssl_server_context *ctx, int prf_id)
{
	unsigned char cpoint[133];
	size_t cpoint_len;
	const br_x509_class **xc;
	const br_x509_pkey *pk;

	xc = ctx->eng.x509ctx;
	pk = (*xc)->get_pkey(xc, NULL);
	cpoint_len = pk->key.ec.qlen;
	if (cpoint_len > sizeof cpoint) {
		/*
		 * If the point is larger than our buffer then we need to
		 * restrict it. Length 2 is not a valid point length, so
		 * the ECDH will fail.
		 */
		cpoint_len = 2;
	}
	memcpy(cpoint, pk->key.ec.q, cpoint_len);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdh(ctx, prf_id, cpoint, cpoint_len);
}

 inline  size_t
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_hash_data(br_ssl_server_context *ctx,
	void *dst, int hash_id, const void *src, size_t len)
{
	const br_hash_class *hf;
	br_hash_compat_context hc;

	if (hash_id == 0) {
		unsigned char tmp[36];

		hf = br_multihash_getimpl(&ctx->eng.mhash, br_md5_ID);
		if (hf == NULL) {
			return 0;
		}
		hf->init(&hc.vtable);
		hf->update(&hc.vtable, src, len);
		hf->out(&hc.vtable, tmp);
		hf = br_multihash_getimpl(&ctx->eng.mhash, br_sha1_ID);
		if (hf == NULL) {
			return 0;
		}
		hf->init(&hc.vtable);
		hf->update(&hc.vtable, src, len);
		hf->out(&hc.vtable, tmp + 16);
		memcpy(dst, tmp, 36);
		return 36;
	} else {
		hf = br_multihash_getimpl(&ctx->eng.mhash, hash_id);
		if (hf == NULL) {
			return 0;
		}
		hf->init(&hc.vtable);
		hf->update(&hc.vtable, src, len);
		hf->out(&hc.vtable, dst);
		return (hf->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
	}
}

/*
 * Do the ECDHE key exchange (part 1: generation of transient key, and
 * computing of the point to send to the client). Returned value is the
 * signature length (in bytes), or -x on error (with x being an error
 * code). The encoded point is written in the ecdhe_point[] context buffer
 * (length in ecdhe_point_len).
 */
 inline  int
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdhe_part1(br_ssl_server_context *ctx, int curve)
{
	unsigned algo_id;
	unsigned mask;
	const unsigned char *order;
	size_t olen, glen;
	size_t hv_len, sig_len;

	if (!((ctx->eng.iec->supported_curves >> curve) & 1)) {
		return -BR_ERR_INVALID_ALGORITHM;
	}
	ctx->eng.ecdhe_curve = curve;

	/*
	 * Generate our private key. We need a non-zero random value
	 * which is lower than the curve order, in a "large enough"
	 * range. We force the top bit to 0 and bottom bit to 1, which
	 * does the trick. Note that contrary to what happens in ECDSA,
	 * this is not a problem if we do not cover the full range of
	 * possible values.
	 */
	order = ctx->eng.iec->order(curve, &olen);
	mask = 0xFF;
	while (mask >= order[0]) {
		mask >>= 1;
	}
	br_hmac_drbg_generate(&ctx->eng.rng, ctx->ecdhe_key, olen);
	ctx->ecdhe_key[0] &= mask;
	ctx->ecdhe_key[olen - 1] |= 0x01;
	ctx->ecdhe_key_len = olen;

	/*
	 * Compute our ECDH point.
	 */
	glen = ctx->eng.iec->mulgen(ctx->eng.ecdhe_point,
		ctx->ecdhe_key, olen, curve);
	ctx->eng.ecdhe_point_len = glen;

	/*
	 * Assemble the message to be signed, and possibly hash it.
	 */
	memcpy(ctx->eng.pad, ctx->eng.client_random, 32);
	memcpy(ctx->eng.pad + 32, ctx->eng.server_random, 32);
	ctx->eng.pad[64 + 0] = 0x03;
	ctx->eng.pad[64 + 1] = 0x00;
	ctx->eng.pad[64 + 2] = curve;
	ctx->eng.pad[64 + 3] = ctx->eng.ecdhe_point_len;
	memcpy(ctx->eng.pad + 64 + 4,
		ctx->eng.ecdhe_point, ctx->eng.ecdhe_point_len);
	hv_len = 64 + 4 + ctx->eng.ecdhe_point_len;
	algo_id = ctx->sign_hash_id;
	if (algo_id >= (unsigned)0xFF00) {
		hv_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_hash_data(ctx, ctx->eng.pad, algo_id & 0xFF,
			ctx->eng.pad, hv_len);
		if (hv_len == 0) {
			return -BR_ERR_INVALID_ALGORITHM;
		}
	}

	sig_len = (*ctx->policy_vtable)->do_sign(ctx->policy_vtable,
		algo_id, ctx->eng.pad, hv_len, sizeof ctx->eng.pad);
	return sig_len ? (int)sig_len : -BR_ERR_INVALID_ALGORITHM;
}

/*
 * Do the ECDHE key exchange (part 2: computation of the shared secret
 * from the point sent by the client).
 */
 inline  void
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdhe_part2(br_ssl_server_context *ctx, int prf_id,
	unsigned char *cpoint, size_t cpoint_len)
{
	int curve;
	uint32_t ctl;
	size_t xoff, xlen;

	curve = ctx->eng.ecdhe_curve;

	/*
	 * Finalise the key exchange.
	 */
	ctl = ctx->eng.iec->mul(cpoint, cpoint_len,
		ctx->ecdhe_key, ctx->ecdhe_key_len, curve);
	xoff = ctx->eng.iec->xoff(curve, &xlen);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ecdh_common(ctx, prf_id, cpoint + xoff, xlen, ctl);

	/*
	 * Clear the ECDHE private key. Forward Secrecy is achieved insofar
	 * as that key does not get stolen, so we'd better destroy it
	 * as soon as it ceases to be useful.
	 */
	memset(ctx->ecdhe_key, 0, ctx->ecdhe_key_len);
}

/*
 * Offset for hash value within the pad (when obtaining all hash values,
 * in preparation for verification of the CertificateVerify message).
 * Order is MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; last value
 * is used to get the total length.
 */
 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_PAD_OFF[] = { 0, 16, 36, 64, 96, 144, 208 };

/*
 * OID for hash functions in RSA signatures.
 */
 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA1[] = {
	0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA224[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA256[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA384[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA512[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

 inline static const unsigned char *_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID[] = {
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA1,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA224,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA256,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA384,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID_SHA512
};

/*
 * Verify the signature in CertificateVerify. Returned value is 0 on
 * success, or a non-zero error code. Lack of implementation of the
 * designated signature algorithm is reported as a "bad signature"
 * error (because it means that the peer did not honour our advertised
 * set of supported signature algorithms).
 */
 inline  int
_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_verify_CV_sig(br_ssl_server_context *ctx, size_t sig_len)
{
	const br_x509_class **xc;
	const br_x509_pkey *pk;
	int id;

	id = ctx->hash_CV_id;
	xc = ctx->eng.x509ctx;
	pk = (*xc)->get_pkey(xc, NULL);
	if (pk->key_type == BR_KEYTYPE_RSA) {
		unsigned char tmp[64];
		const unsigned char *hash_oid;

		if (id == 0) {
			hash_oid = NULL;
		} else {
			hash_oid = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_OID[id - 2];
		}
		if (ctx->eng.irsavrfy == 0) {
			return BR_ERR_BAD_SIGNATURE;
		}
		if (!ctx->eng.irsavrfy(ctx->eng.pad, sig_len,
			hash_oid, ctx->hash_CV_len, &pk->key.rsa, tmp)
			|| memcmp(tmp, ctx->hash_CV, ctx->hash_CV_len) != 0)
		{
			return BR_ERR_BAD_SIGNATURE;
		}
	} else {
		if (ctx->eng.iecdsa == 0) {
			return BR_ERR_BAD_SIGNATURE;
		}
		if (!ctx->eng.iecdsa(ctx->eng.iec,
			ctx->hash_CV, ctx->hash_CV_len,
			&pk->key.ec, ctx->eng.pad, sig_len))
		{
			return BR_ERR_BAD_SIGNATURE;
		}
	}
	return 0;
}



 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_datablock[] = {
	0x00, 0x00, 0x0A, 0x00, 0x24, 0x00, 0x2F, 0x01, 0x24, 0x00, 0x35, 0x02,
	0x24, 0x00, 0x3C, 0x01, 0x44, 0x00, 0x3D, 0x02, 0x44, 0x00, 0x9C, 0x03,
	0x04, 0x00, 0x9D, 0x04, 0x05, 0xC0, 0x03, 0x40, 0x24, 0xC0, 0x04, 0x41,
	0x24, 0xC0, 0x05, 0x42, 0x24, 0xC0, 0x08, 0x20, 0x24, 0xC0, 0x09, 0x21,
	0x24, 0xC0, 0x0A, 0x22, 0x24, 0xC0, 0x0D, 0x30, 0x24, 0xC0, 0x0E, 0x31,
	0x24, 0xC0, 0x0F, 0x32, 0x24, 0xC0, 0x12, 0x10, 0x24, 0xC0, 0x13, 0x11,
	0x24, 0xC0, 0x14, 0x12, 0x24, 0xC0, 0x23, 0x21, 0x44, 0xC0, 0x24, 0x22,
	0x55, 0xC0, 0x25, 0x41, 0x44, 0xC0, 0x26, 0x42, 0x55, 0xC0, 0x27, 0x11,
	0x44, 0xC0, 0x28, 0x12, 0x55, 0xC0, 0x29, 0x31, 0x44, 0xC0, 0x2A, 0x32,
	0x55, 0xC0, 0x2B, 0x23, 0x04, 0xC0, 0x2C, 0x24, 0x05, 0xC0, 0x2D, 0x43,
	0x04, 0xC0, 0x2E, 0x44, 0x05, 0xC0, 0x2F, 0x13, 0x04, 0xC0, 0x30, 0x14,
	0x05, 0xC0, 0x31, 0x33, 0x04, 0xC0, 0x32, 0x34, 0x05, 0xCC, 0xA8, 0x15,
	0x04, 0xCC, 0xA9, 0x25, 0x04, 0x00, 0x00
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_codeblock[] = {
	0x00, 0x01, 0x00, 0x0B, 0x00, 0x00, 0x01, 0x00, 0x0E, 0x00, 0x00, 0x01,
	0x00, 0x0F, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x01, 0x01, 0x08,
	0x00, 0x00, 0x01, 0x01, 0x09, 0x00, 0x00, 0x01, 0x02, 0x08, 0x00, 0x00,
	0x01, 0x02, 0x09, 0x00, 0x00, 0x29, 0x29, 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_CCS), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_FINISHED), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_FRAGLEN), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_HANDSHAKE), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_PARAM), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_SECRENEG), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_SIGNATURE), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_BAD_VERSION), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_INVALID_ALGORITHM), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_LIMIT_EXCEEDED), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_NO_CLIENT_AUTH), 0x00, 0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_OK),
	0x00, 0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_OVERSIZED_ID), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_UNEXPECTED), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT1(BR_ERR_WRONG_KEY_USAGE), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, action)), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, alert)), 0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, application_data)), 0x00, 0x00,
	0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, session) + offsetof(br_ssl_session_parameters, cipher_suite)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_server_context, client_max_version)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, client_random)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_server_context, client_suites)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_server_context, client_suites_num)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, close_received)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_server_context, curves)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, ecdhe_point)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, ecdhe_point_len)),
	0x00, 0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, flags)),
	0x00, 0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_server_context, hashes)),
	0x00, 0x00, 0x79, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(BR_MAX_CIPHER_SUITES * sizeof(br_suite_translated)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, log_max_frag_len)),
	0x00, 0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, pad)), 0x00,
	0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, peer_log_max_frag_len)), 0x00,
	0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, protocol_names_num)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, record_type_in)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, record_type_out)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, reneg)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, saved_finished)), 0x00,
	0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, selected_protocol)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, server_name)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, server_random)), 0x00, 0x00,
	0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, session) + offsetof(br_ssl_session_parameters, session_id)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, session) + offsetof(br_ssl_session_parameters, session_id_len)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, shutdown_recv)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_server_context, sign_hash_id)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, suites_buf)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, suites_num)), 0x00,
	0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, session) + offsetof(br_ssl_session_parameters, version)),
	0x00, 0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, version_in)),
	0x00, 0x00, 0x01,
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, version_max)), 0x00, 0x00,
	0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, version_min)), 0x00,
	0x00, 0x01, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INT2(offsetof(br_ssl_engine_context, version_out)),
	0x00, 0x00, 0x09, 0x2A, 0x5B, 0x06, 0x02, 0x68, 0x2B, 0x00, 0x00, 0x01,
	0x01, 0x00, 0x01, 0x03, 0x00, 0x99, 0x2A, 0x61, 0x47, 0x9D, 0x2A, 0x05,
	0x04, 0x63, 0x01, 0x00, 0x00, 0x02, 0x00, 0x0F, 0x06, 0x02, 0x9D, 0x00,
	0x61, 0x04, 0x6B, 0x00, 0x06, 0x02, 0x68, 0x2B, 0x00, 0x00, 0x2A, 0x89,
	0x47, 0x05, 0x03, 0x01, 0x0C, 0x08, 0x47, 0x76, 0x2E, 0xA6, 0x1C, 0x83,
	0x01, 0x0C, 0x33, 0x00, 0x00, 0x2A, 0x22, 0x01, 0x08, 0x0C, 0x47, 0x5F,
	0x22, 0x08, 0x00, 0x01, 0x03, 0x00, 0x01, 0x00, 0x75, 0x42, 0x2C, 0x19,
	0x38, 0x06, 0x07, 0x02, 0x00, 0xCD, 0x03, 0x00, 0x04, 0x75, 0x01, 0x00,
	0xC5, 0x02, 0x00, 0x2A, 0x19, 0x13, 0x06, 0x02, 0x6F, 0x2B, 0xCD, 0x04,
	0x76, 0x00, 0x01, 0x00, 0x75, 0x42, 0x01, 0x16, 0x87, 0x42, 0x01, 0x00,
	0x8A, 0x40, 0x36, 0xAF, 0x35, 0x06, 0x02, 0x71, 0x2B, 0x06, 0x0A, 0xD4,
	0x01, 0x00, 0xD0, 0x01, 0x00, 0xAB, 0x04, 0x80, 0x46, 0xD4, 0xD1, 0x29,
	0xD6, 0x4E, 0x06, 0x01, 0xD2, 0xD5, 0x2C, 0x4E, 0x06, 0x31, 0x01, 0x00,
	0xAC, 0x2A, 0x5B, 0x06, 0x0F, 0x01, 0x02, 0xA2, 0x05, 0x02, 0x37, 0x2B,
	0x29, 0xB0, 0xAE, 0x2A, 0xC6, 0x29, 0x04, 0x19, 0x2A, 0x5D, 0x06, 0x0B,
	0x29, 0x01, 0x02, 0xA2, 0x05, 0x02, 0x6E, 0x2B, 0xB0, 0x04, 0x0A, 0xB2,
	0x2A, 0x05, 0x04, 0x29, 0xA9, 0x04, 0x02, 0xB1, 0xAD, 0x04, 0x01, 0xB0,
	0x01, 0x00, 0xAB, 0x01, 0x00, 0xD0, 0x3E, 0x01, 0x01, 0x75, 0x42, 0x01,
	0x17, 0x87, 0x42, 0x00, 0x00, 0x3A, 0x3A, 0x00, 0x01, 0x03, 0x00, 0x2C,
	0x19, 0x38, 0x06, 0x04, 0xCC, 0x29, 0x04, 0x78, 0x01, 0x02, 0x02, 0x00,
	0xC4, 0x19, 0x38, 0x06, 0x04, 0xCC, 0x29, 0x04, 0x78, 0x02, 0x00, 0x01,
	0x84, 0x00, 0x08, 0x2B, 0x00, 0x00, 0x7F, 0x2F, 0x47, 0x12, 0x01, 0x01,
	0x13, 0x37, 0x00, 0x00, 0x2A, 0x05, 0x04, 0x29, 0x01, 0x7F, 0x00, 0x01,
	0x00, 0xA0, 0x12, 0x01, 0x01, 0x13, 0x5D, 0x06, 0x03, 0x5F, 0x04, 0x75,
	0x47, 0x29, 0x00, 0x00, 0x01, 0x7F, 0x9F, 0xCC, 0x2A, 0x01, 0x07, 0x13,
	0x01, 0x00, 0x3A, 0x0F, 0x06, 0x09, 0x29, 0x01, 0x10, 0x13, 0x06, 0x01,
	0xC3, 0x04, 0x2A, 0x01, 0x01, 0x3A, 0x0F, 0x06, 0x21, 0x29, 0x29, 0x88,
	0x30, 0x01, 0x01, 0x0F, 0x01, 0x01, 0xA2, 0x39, 0x06, 0x0F, 0x2C, 0x19,
	0x38, 0x06, 0x04, 0xCC, 0x29, 0x04, 0x78, 0x01, 0x80, 0x64, 0xC5, 0x04,
	0x03, 0x01, 0x00, 0x9F, 0x04, 0x03, 0x71, 0x2B, 0x29, 0x04, 0x40, 0x01,
	0x2A, 0x03, 0x00, 0x09, 0x2A, 0x5B, 0x06, 0x02, 0x68, 0x2B, 0x02, 0x00,
	0x00, 0x00, 0x9A, 0x01, 0x0F, 0x13, 0x00, 0x00, 0x74, 0x30, 0x01, 0x00,
	0x3A, 0x0F, 0x06, 0x10, 0x29, 0x2A, 0x01, 0x01, 0x0E, 0x06, 0x03, 0x29,
	0x01, 0x02, 0x74, 0x42, 0x01, 0x00, 0x04, 0x21, 0x01, 0x01, 0x3A, 0x0F,
	0x06, 0x14, 0x29, 0x01, 0x00, 0x74, 0x42, 0x2A, 0x01, 0x80, 0x64, 0x0F,
	0x06, 0x05, 0x01, 0x82, 0x00, 0x08, 0x2B, 0x5D, 0x04, 0x07, 0x29, 0x01,
	0x82, 0x00, 0x08, 0x2B, 0x29, 0x00, 0x00, 0x01, 0x00, 0x31, 0x06, 0x05,
	0x3D, 0xA7, 0x39, 0x04, 0x78, 0x2A, 0x06, 0x04, 0x01, 0x01, 0x8F, 0x42,
	0x00, 0x00, 0x01, 0x1F, 0x13, 0x01, 0x12, 0x0F, 0x05, 0x02, 0x72, 0x2B,
	0x76, 0x2E, 0x2A, 0xC8, 0x05, 0x02, 0x71, 0x2B, 0xA6, 0x28, 0x00, 0x02,
	0x85, 0x2E, 0x05, 0x02, 0xBA, 0x00, 0xBE, 0xA5, 0xBE, 0xA5, 0x01, 0x7E,
	0x03, 0x00, 0x2A, 0x06, 0x17, 0xC0, 0x2A, 0x03, 0x01, 0x83, 0x47, 0xB4,
	0x02, 0x01, 0x4F, 0x2A, 0x02, 0x00, 0x51, 0x06, 0x04, 0x03, 0x00, 0x04,
	0x01, 0x29, 0x04, 0x66, 0x9B, 0x9B, 0x02, 0x00, 0x5F, 0x8A, 0x40, 0x00,
	0x00, 0x31, 0x06, 0x0B, 0x86, 0x30, 0x01, 0x14, 0x0E, 0x06, 0x02, 0x71,
	0x2B, 0x04, 0x11, 0xCC, 0x01, 0x07, 0x13, 0x2A, 0x01, 0x02, 0x0E, 0x06,
	0x06, 0x06, 0x02, 0x71, 0x2B, 0x04, 0x70, 0x29, 0xC1, 0x01, 0x01, 0x0E,
	0x35, 0x39, 0x06, 0x02, 0x64, 0x2B, 0x2A, 0x01, 0x01, 0xC7, 0x38, 0xB3,
	0x00, 0x01, 0xB8, 0x01, 0x0B, 0x0F, 0x05, 0x02, 0x71, 0x2B, 0x2A, 0x01,
	0x03, 0x0F, 0x06, 0x08, 0xBF, 0x06, 0x02, 0x68, 0x2B, 0x47, 0x29, 0x00,
	0x47, 0x5A, 0xBF, 0xA5, 0x2A, 0x06, 0x23, 0xBF, 0xA5, 0x2A, 0x59, 0x2A,
	0x06, 0x18, 0x2A, 0x01, 0x82, 0x00, 0x10, 0x06, 0x05, 0x01, 0x82, 0x00,
	0x04, 0x01, 0x2A, 0x03, 0x00, 0x83, 0x02, 0x00, 0xB4, 0x02, 0x00, 0x56,
	0x04, 0x65, 0x9B, 0x57, 0x04, 0x5A, 0x9B, 0x9B, 0x58, 0x2A, 0x06, 0x02,
	0x37, 0x00, 0x29, 0x2D, 0x00, 0x02, 0x2A, 0x01, 0x20, 0x13, 0x05, 0x02,
	0x72, 0x2B, 0x01, 0x0F, 0x13, 0x03, 0x00, 0xAE, 0x93, 0x2E, 0x01, 0x86,
	0x03, 0x11, 0x06, 0x23, 0xBE, 0x2A, 0x01, 0x81, 0x7F, 0x13, 0x5F, 0x01,
	0x01, 0x12, 0x02, 0x00, 0x0F, 0x05, 0x02, 0x6A, 0x2B, 0x01, 0x08, 0x12,
	0x2A, 0x01, 0x02, 0x0B, 0x3A, 0x01, 0x06, 0x10, 0x39, 0x06, 0x02, 0x6C,
	0x2B, 0x04, 0x0D, 0x02, 0x00, 0x01, 0x01, 0x0F, 0x06, 0x04, 0x01, 0x00,
	0x04, 0x02, 0x01, 0x02, 0x20, 0x05, 0x02, 0x6C, 0x2B, 0xBE, 0x2A, 0x03,
	0x01, 0x2A, 0x01, 0x84, 0x00, 0x10, 0x06, 0x02, 0x6D, 0x2B, 0x83, 0x47,
	0xB4, 0x02, 0x01, 0x53, 0x2A, 0x06, 0x01, 0x2B, 0x29, 0x9B, 0x00, 0x00,
	0x1D, 0xB8, 0x01, 0x0F, 0x0F, 0x05, 0x02, 0x71, 0x2B, 0x00, 0x0A, 0xB8,
	0x01, 0x01, 0x0F, 0x05, 0x02, 0x71, 0x2B, 0xBE, 0x2A, 0x03, 0x00, 0x77,
	0x40, 0x78, 0x01, 0x20, 0xB4, 0xC0, 0x2A, 0x01, 0x20, 0x10, 0x06, 0x02,
	0x70, 0x2B, 0x2A, 0x8E, 0x42, 0x8D, 0x47, 0xB4, 0x1A, 0x03, 0x01, 0xBE,
	0xA5, 0x01, 0x00, 0x03, 0x02, 0x01, 0x00, 0x03, 0x03, 0x81, 0xA0, 0x17,
	0x3A, 0x08, 0x03, 0x04, 0x03, 0x05, 0x2A, 0x06, 0x80, 0x6D, 0xBE, 0x2A,
	0x03, 0x06, 0x02, 0x01, 0x06, 0x0A, 0x2A, 0x76, 0x2E, 0x0F, 0x06, 0x04,
	0x01, 0x7F, 0x03, 0x03, 0x2A, 0x01, 0x81, 0x7F, 0x0F, 0x06, 0x0A, 0x88,
	0x30, 0x06, 0x02, 0x69, 0x2B, 0x01, 0x7F, 0x03, 0x02, 0x2A, 0x01, 0x81,
	0xAC, 0x00, 0x0F, 0x06, 0x11, 0x02, 0x00, 0x96, 0x2E, 0x11, 0x02, 0x00,
	0x95, 0x2E, 0x0B, 0x13, 0x06, 0x04, 0x01, 0x7F, 0x03, 0x00, 0xC2, 0x2A,
	0x5B, 0x06, 0x03, 0x29, 0x04, 0x26, 0x01, 0x00, 0xA2, 0x06, 0x0B, 0x01,
	0x02, 0x0C, 0x79, 0x08, 0x02, 0x06, 0x47, 0x40, 0x04, 0x16, 0x29, 0x02,
	0x05, 0x02, 0x04, 0x11, 0x06, 0x02, 0x67, 0x2B, 0x02, 0x06, 0x02, 0x05,
	0x40, 0x02, 0x05, 0x01, 0x04, 0x08, 0x03, 0x05, 0x04, 0xFF, 0x0F, 0x29,
	0x01, 0x00, 0x03, 0x07, 0xC0, 0xA5, 0x2A, 0x06, 0x09, 0xC0, 0x05, 0x04,
	0x01, 0x7F, 0x03, 0x07, 0x04, 0x74, 0x9B, 0x01, 0x00, 0x8B, 0x42, 0x01,
	0x88, 0x04, 0x80, 0x41, 0x01, 0x84, 0x80, 0x80, 0x00, 0x7C, 0x41, 0x2A,
	0x06, 0x80, 0x4E, 0xBE, 0xA5, 0x2A, 0x06, 0x80, 0x47, 0xBE, 0x01, 0x00,
	0x3A, 0x0F, 0x06, 0x04, 0x29, 0xB7, 0x04, 0x39, 0x01, 0x01, 0x3A, 0x0F,
	0x06, 0x04, 0x29, 0xB5, 0x04, 0x2F, 0x01, 0x83, 0xFE, 0x01, 0x3A, 0x0F,
	0x06, 0x04, 0x29, 0xB6, 0x04, 0x23, 0x01, 0x0D, 0x3A, 0x0F, 0x06, 0x04,
	0x29, 0xBC, 0x04, 0x19, 0x01, 0x0A, 0x3A, 0x0F, 0x06, 0x04, 0x29, 0xBD,
	0x04, 0x0F, 0x01, 0x10, 0x3A, 0x0F, 0x06, 0x04, 0x29, 0xAA, 0x04, 0x05,
	0x29, 0xBA, 0x01, 0x00, 0x29, 0x04, 0xFF, 0x35, 0x9B, 0x9B, 0x02, 0x01,
	0x02, 0x03, 0x13, 0x03, 0x01, 0x02, 0x00, 0x5B, 0x06, 0x08, 0x77, 0x2E,
	0x97, 0x40, 0x01, 0x80, 0x56, 0xA1, 0x95, 0x2E, 0x2A, 0x02, 0x00, 0x10,
	0x06, 0x03, 0x29, 0x02, 0x00, 0x2A, 0x01, 0x86, 0x00, 0x0B, 0x06, 0x02,
	0x6B, 0x2B, 0x02, 0x00, 0x96, 0x2E, 0x0B, 0x06, 0x04, 0x01, 0x80, 0x46,
	0xA1, 0x02, 0x01, 0x06, 0x10, 0x93, 0x2E, 0x02, 0x00, 0x0D, 0x06, 0x05,
	0x29, 0x93, 0x2E, 0x04, 0x04, 0x01, 0x00, 0x03, 0x01, 0x2A, 0x93, 0x40,
	0x2A, 0x94, 0x40, 0x2A, 0x97, 0x40, 0x01, 0x86, 0x03, 0x11, 0x03, 0x08,
	0x02, 0x02, 0x06, 0x04, 0x01, 0x02, 0x88, 0x42, 0x02, 0x07, 0x05, 0x03,
	0x01, 0x28, 0xA1, 0x44, 0x29, 0x01, 0x82, 0x01, 0x07, 0x01, 0xFC, 0x80,
	0x00, 0x39, 0x80, 0x2F, 0x13, 0x2A, 0x80, 0x41, 0x2A, 0x01, 0x81, 0x7F,
	0x13, 0x5C, 0x37, 0x47, 0x01, 0x08, 0x12, 0x5C, 0x01, 0x02, 0x13, 0x39,
	0x01, 0x0C, 0x0C, 0x03, 0x09, 0x7C, 0x2F, 0x43, 0x13, 0x2A, 0x7C, 0x41,
	0x05, 0x04, 0x01, 0x00, 0x03, 0x09, 0x02, 0x01, 0x06, 0x03, 0x01, 0x7F,
	0x00, 0x8D, 0x01, 0x20, 0x34, 0x01, 0x20, 0x8E, 0x42, 0x79, 0x2A, 0x03,
	0x05, 0x2A, 0x02, 0x04, 0x0B, 0x06, 0x80, 0x49, 0x2A, 0x2E, 0x2A, 0x9A,
	0x2A, 0x01, 0x0C, 0x12, 0x2A, 0x01, 0x01, 0x0F, 0x47, 0x01, 0x02, 0x0F,
	0x39, 0x06, 0x0A, 0x2A, 0x02, 0x09, 0x13, 0x05, 0x04, 0x63, 0x01, 0x00,
	0x2A, 0x02, 0x08, 0x05, 0x0E, 0x2A, 0x01, 0x81, 0x70, 0x13, 0x01, 0x20,
	0x0E, 0x06, 0x04, 0x63, 0x01, 0x00, 0x2A, 0x2A, 0x06, 0x10, 0x02, 0x05,
	0x61, 0x40, 0x02, 0x05, 0x40, 0x02, 0x05, 0x01, 0x04, 0x08, 0x03, 0x05,
	0x04, 0x01, 0x63, 0x01, 0x04, 0x08, 0x04, 0xFF, 0x30, 0x29, 0x02, 0x05,
	0x79, 0x09, 0x01, 0x02, 0x12, 0x2A, 0x05, 0x03, 0x01, 0x28, 0xA1, 0x7A,
	0x42, 0x8A, 0x2E, 0x01, 0x83, 0xFF, 0x7F, 0x0F, 0x06, 0x0D, 0x01, 0x03,
	0xA2, 0x06, 0x04, 0x01, 0x80, 0x78, 0xA1, 0x01, 0x00, 0x8A, 0x40, 0x18,
	0x05, 0x03, 0x01, 0x28, 0xA1, 0x01, 0x00, 0x00, 0x00, 0xB2, 0xB1, 0x00,
	0x04, 0x76, 0x2E, 0xCB, 0x06, 0x16, 0xBE, 0x2A, 0x01, 0x84, 0x00, 0x10,
	0x06, 0x02, 0x6D, 0x2B, 0x2A, 0x03, 0x00, 0x83, 0x47, 0xB4, 0x02, 0x00,
	0x76, 0x2E, 0xA6, 0x27, 0x76, 0x2E, 0x2A, 0xC9, 0x47, 0xC8, 0x03, 0x01,
	0x03, 0x02, 0x02, 0x01, 0x02, 0x02, 0x39, 0x06, 0x14, 0xC0, 0x2A, 0x03,
	0x03, 0x83, 0x47, 0xB4, 0x02, 0x03, 0x76, 0x2E, 0xA6, 0x02, 0x02, 0x06,
	0x03, 0x26, 0x04, 0x01, 0x24, 0x9B, 0x00, 0x00, 0xB8, 0x01, 0x10, 0x0F,
	0x05, 0x02, 0x71, 0x2B, 0x00, 0x00, 0x9C, 0xB8, 0x01, 0x14, 0x0E, 0x06,
	0x02, 0x71, 0x2B, 0x83, 0x01, 0x0C, 0x08, 0x01, 0x0C, 0xB4, 0x9B, 0x83,
	0x2A, 0x01, 0x0C, 0x08, 0x01, 0x0C, 0x32, 0x05, 0x02, 0x65, 0x2B, 0x00,
	0x02, 0x03, 0x00, 0x03, 0x01, 0x02, 0x00, 0x98, 0x02, 0x01, 0x02, 0x00,
	0x3C, 0x2A, 0x01, 0x00, 0x0F, 0x06, 0x02, 0x63, 0x00, 0xCE, 0x04, 0x74,
	0x00, 0xBE, 0x01, 0x01, 0x0E, 0x06, 0x02, 0x66, 0x2B, 0xC0, 0x2A, 0x2A,
	0x5D, 0x47, 0x01, 0x05, 0x11, 0x39, 0x06, 0x02, 0x66, 0x2B, 0x01, 0x08,
	0x08, 0x2A, 0x82, 0x30, 0x0B, 0x06, 0x0D, 0x2A, 0x01, 0x01, 0x47, 0x0C,
	0x3F, 0x2A, 0x82, 0x42, 0x84, 0x42, 0x04, 0x01, 0x29, 0x00, 0x00, 0xBE,
	0x88, 0x30, 0x01, 0x00, 0x3A, 0x0F, 0x06, 0x13, 0x29, 0x01, 0x01, 0x0F,
	0x05, 0x02, 0x69, 0x2B, 0xC0, 0x06, 0x02, 0x69, 0x2B, 0x01, 0x02, 0x88,
	0x42, 0x04, 0x28, 0x01, 0x02, 0x3A, 0x0F, 0x06, 0x1F, 0x29, 0x01, 0x0D,
	0x0F, 0x05, 0x02, 0x69, 0x2B, 0xC0, 0x01, 0x0C, 0x0F, 0x05, 0x02, 0x69,
	0x2B, 0x83, 0x01, 0x0C, 0xB4, 0x89, 0x83, 0x01, 0x0C, 0x32, 0x05, 0x02,
	0x69, 0x2B, 0x04, 0x03, 0x69, 0x2B, 0x29, 0x00, 0x00, 0xBE, 0xA5, 0xBE,
	0xA5, 0x2A, 0x06, 0x1D, 0xC0, 0x06, 0x03, 0xBA, 0x04, 0x15, 0xBE, 0x2A,
	0x01, 0x81, 0x7F, 0x0D, 0x06, 0x0C, 0x2A, 0x8B, 0x08, 0x01, 0x00, 0x47,
	0x42, 0x8B, 0x47, 0xB4, 0x04, 0x01, 0xC6, 0x04, 0x60, 0x9B, 0x9B, 0x00,
	0x00, 0xB9, 0x2A, 0x5D, 0x06, 0x07, 0x29, 0x06, 0x02, 0x67, 0x2B, 0x04,
	0x74, 0x00, 0x00, 0xC1, 0x01, 0x03, 0xBF, 0x47, 0x29, 0x47, 0x00, 0x00,
	0xBE, 0xC6, 0x00, 0x03, 0x01, 0x00, 0x03, 0x00, 0xBE, 0xA5, 0x2A, 0x06,
	0x80, 0x50, 0xC0, 0x03, 0x01, 0xC0, 0x03, 0x02, 0x02, 0x01, 0x01, 0x08,
	0x0F, 0x06, 0x16, 0x02, 0x02, 0x01, 0x0F, 0x0D, 0x06, 0x0D, 0x01, 0x01,
	0x02, 0x02, 0x01, 0x10, 0x08, 0x0C, 0x02, 0x00, 0x39, 0x03, 0x00, 0x04,
	0x2A, 0x02, 0x01, 0x01, 0x02, 0x11, 0x02, 0x01, 0x01, 0x06, 0x0D, 0x13,
	0x02, 0x02, 0x01, 0x01, 0x0F, 0x02, 0x02, 0x01, 0x03, 0x0F, 0x39, 0x13,
	0x06, 0x11, 0x02, 0x00, 0x01, 0x01, 0x02, 0x02, 0x60, 0x01, 0x02, 0x0C,
	0x02, 0x01, 0x08, 0x0C, 0x39, 0x03, 0x00, 0x04, 0xFF, 0x2C, 0x9B, 0x02,
	0x00, 0x00, 0x00, 0xBE, 0xA5, 0xBB, 0x80, 0x41, 0x9B, 0x00, 0x00, 0xBE,
	0xA5, 0xBE, 0xA5, 0x01, 0x00, 0x7C, 0x41, 0x2A, 0x06, 0x15, 0xBE, 0x2A,
	0x01, 0x20, 0x0B, 0x06, 0x0B, 0x01, 0x01, 0x47, 0x0C, 0x7C, 0x2F, 0x39,
	0x7C, 0x41, 0x04, 0x01, 0x29, 0x04, 0x68, 0x9B, 0x9B, 0x00, 0x00, 0x01,
	0x02, 0x98, 0xC1, 0x01, 0x08, 0x0C, 0xC1, 0x08, 0x00, 0x00, 0x01, 0x03,
	0x98, 0xC1, 0x01, 0x08, 0x0C, 0xC1, 0x08, 0x01, 0x08, 0x0C, 0xC1, 0x08,
	0x00, 0x00, 0x01, 0x01, 0x98, 0xC1, 0x00, 0x00, 0x3D, 0x2A, 0x5B, 0x05,
	0x01, 0x00, 0x29, 0xCE, 0x04, 0x76, 0x02, 0x03, 0x00, 0x92, 0x30, 0x03,
	0x01, 0x01, 0x00, 0x2A, 0x02, 0x01, 0x0B, 0x06, 0x10, 0x2A, 0x01, 0x01,
	0x0C, 0x91, 0x08, 0x2E, 0x02, 0x00, 0x0F, 0x06, 0x01, 0x00, 0x5F, 0x04,
	0x6A, 0x29, 0x01, 0x7F, 0x00, 0x00, 0x2C, 0x19, 0x38, 0x06, 0x04, 0xCC,
	0x29, 0x04, 0x78, 0x01, 0x16, 0x87, 0x42, 0x01, 0x00, 0xDF, 0x01, 0x00,
	0xDE, 0x2C, 0x01, 0x17, 0x87, 0x42, 0x00, 0x00, 0x01, 0x15, 0x87, 0x42,
	0x47, 0x55, 0x29, 0x55, 0x29, 0x2C, 0x00, 0x00, 0x01, 0x01, 0x47, 0xC4,
	0x00, 0x00, 0x47, 0x3A, 0x98, 0x47, 0x2A, 0x06, 0x05, 0xC1, 0x29, 0x60,
	0x04, 0x78, 0x29, 0x00, 0x02, 0x03, 0x00, 0x76, 0x2E, 0x9A, 0x03, 0x01,
	0x02, 0x01, 0x01, 0x0F, 0x13, 0x02, 0x01, 0x01, 0x04, 0x12, 0x01, 0x0F,
	0x13, 0x02, 0x01, 0x01, 0x08, 0x12, 0x01, 0x0F, 0x13, 0x01, 0x00, 0x3A,
	0x0F, 0x06, 0x10, 0x29, 0x01, 0x00, 0x01, 0x18, 0x02, 0x00, 0x06, 0x03,
	0x4A, 0x04, 0x01, 0x4B, 0x04, 0x80, 0x68, 0x01, 0x01, 0x3A, 0x0F, 0x06,
	0x10, 0x29, 0x01, 0x01, 0x01, 0x10, 0x02, 0x00, 0x06, 0x03, 0x4A, 0x04,
	0x01, 0x4B, 0x04, 0x80, 0x52, 0x01, 0x02, 0x3A, 0x0F, 0x06, 0x0F, 0x29,
	0x01, 0x01, 0x01, 0x20, 0x02, 0x00, 0x06, 0x03, 0x4A, 0x04, 0x01, 0x4B,
	0x04, 0x3D, 0x01, 0x03, 0x3A, 0x0F, 0x06, 0x0E, 0x29, 0x29, 0x01, 0x10,
	0x02, 0x00, 0x06, 0x03, 0x48, 0x04, 0x01, 0x49, 0x04, 0x29, 0x01, 0x04,
	0x3A, 0x0F, 0x06, 0x0E, 0x29, 0x29, 0x01, 0x20, 0x02, 0x00, 0x06, 0x03,
	0x48, 0x04, 0x01, 0x49, 0x04, 0x15, 0x01, 0x05, 0x3A, 0x0F, 0x06, 0x0C,
	0x29, 0x29, 0x02, 0x00, 0x06, 0x03, 0x4C, 0x04, 0x01, 0x4D, 0x04, 0x03,
	0x68, 0x2B, 0x29, 0x00, 0x00, 0x9A, 0x01, 0x0C, 0x12, 0x01, 0x02, 0x10,
	0x00, 0x00, 0x9A, 0x01, 0x0C, 0x12, 0x2A, 0x5E, 0x47, 0x01, 0x03, 0x0B,
	0x13, 0x00, 0x00, 0x9A, 0x01, 0x0C, 0x12, 0x01, 0x01, 0x0F, 0x00, 0x00,
	0x9A, 0x01, 0x0C, 0x12, 0x5D, 0x00, 0x00, 0x1B, 0x01, 0x00, 0x73, 0x30,
	0x2A, 0x06, 0x1F, 0x01, 0x01, 0x3A, 0x0F, 0x06, 0x06, 0x29, 0x01, 0x00,
	0x9E, 0x04, 0x11, 0x01, 0x02, 0x3A, 0x0F, 0x06, 0x0A, 0x29, 0x75, 0x30,
	0x06, 0x03, 0x01, 0x10, 0x39, 0x04, 0x01, 0x29, 0x04, 0x01, 0x29, 0x7B,
	0x30, 0x05, 0x33, 0x31, 0x06, 0x30, 0x86, 0x30, 0x01, 0x14, 0x3A, 0x0F,
	0x06, 0x06, 0x29, 0x01, 0x02, 0x39, 0x04, 0x22, 0x01, 0x15, 0x3A, 0x0F,
	0x06, 0x09, 0x29, 0xA8, 0x06, 0x03, 0x01, 0x7F, 0x9E, 0x04, 0x13, 0x01,
	0x16, 0x3A, 0x0F, 0x06, 0x06, 0x29, 0x01, 0x01, 0x39, 0x04, 0x07, 0x29,
	0x01, 0x04, 0x39, 0x01, 0x00, 0x29, 0x19, 0x06, 0x03, 0x01, 0x08, 0x39,
	0x00, 0x00, 0x1B, 0x2A, 0x05, 0x0F, 0x31, 0x06, 0x0C, 0x86, 0x30, 0x01,
	0x15, 0x0F, 0x06, 0x04, 0x29, 0xA8, 0x04, 0x01, 0x23, 0x00, 0x00, 0xCC,
	0x01, 0x07, 0x13, 0x01, 0x01, 0x10, 0x06, 0x02, 0x71, 0x2B, 0x00, 0x01,
	0x03, 0x00, 0x2C, 0x19, 0x06, 0x05, 0x02, 0x00, 0x87, 0x42, 0x00, 0xCC,
	0x29, 0x04, 0x74, 0x00, 0x01, 0x14, 0xCF, 0x01, 0x01, 0xDF, 0x2C, 0x2A,
	0x01, 0x00, 0xC7, 0x01, 0x16, 0xCF, 0xD3, 0x2C, 0x00, 0x00, 0x01, 0x0B,
	0xDF, 0x50, 0x2A, 0x2A, 0x01, 0x03, 0x08, 0xDE, 0xDE, 0x14, 0x2A, 0x5B,
	0x06, 0x02, 0x29, 0x00, 0xDE, 0x1E, 0x2A, 0x06, 0x05, 0x83, 0x47, 0xD7,
	0x04, 0x77, 0x29, 0x04, 0x6C, 0x00, 0x01, 0x00, 0xD9, 0x93, 0x2E, 0x01,
	0x86, 0x03, 0x11, 0x06, 0x05, 0x61, 0x01, 0x00, 0xDA, 0x08, 0x4E, 0x08,
	0x01, 0x03, 0x08, 0x01, 0x0D, 0xDF, 0xDE, 0x01, 0x00, 0xD9, 0xDF, 0x01,
	0x01, 0xD9, 0x29, 0x93, 0x2E, 0x01, 0x86, 0x03, 0x11, 0x06, 0x08, 0x01,
	0x00, 0xDA, 0xDD, 0x01, 0x01, 0xDA, 0x29, 0x4E, 0xDD, 0x16, 0x15, 0x2A,
	0x5B, 0x06, 0x02, 0x29, 0x00, 0xDD, 0x1F, 0x2A, 0x06, 0x05, 0x83, 0x47,
	0xD7, 0x04, 0x77, 0x29, 0x04, 0x6C, 0x00, 0x9C, 0x01, 0x14, 0xDF, 0x01,
	0x0C, 0xDE, 0x83, 0x01, 0x0C, 0xD7, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
	0xDF, 0x01, 0x80, 0x46, 0x88, 0x30, 0x01, 0x02, 0x0F, 0x06, 0x0C, 0x02,
	0x00, 0x06, 0x04, 0x01, 0x05, 0x04, 0x02, 0x01, 0x1D, 0x04, 0x02, 0x01,
	0x00, 0x03, 0x01, 0x84, 0x30, 0x06, 0x04, 0x01, 0x05, 0x04, 0x02, 0x01,
	0x00, 0x03, 0x02, 0x8A, 0x2E, 0x2A, 0x06, 0x05, 0x60, 0x21, 0x01, 0x07,
	0x08, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x02, 0x03, 0x08, 0x2A,
	0x06, 0x03, 0x01, 0x02, 0x08, 0x08, 0xDE, 0x93, 0x2E, 0xDD, 0x8C, 0x01,
	0x04, 0x17, 0x8C, 0x01, 0x04, 0x08, 0x01, 0x1C, 0x34, 0x8C, 0x01, 0x20,
	0xD7, 0x01, 0x20, 0xDF, 0x8D, 0x01, 0x20, 0xD7, 0x76, 0x2E, 0xDD, 0x01,
	0x00, 0xDF, 0x02, 0x01, 0x02, 0x02, 0x08, 0x02, 0x03, 0x08, 0x2A, 0x06,
	0x80, 0x40, 0xDD, 0x02, 0x01, 0x2A, 0x06, 0x10, 0x01, 0x83, 0xFE, 0x01,
	0xDD, 0x01, 0x04, 0x09, 0x2A, 0xDD, 0x60, 0x89, 0x47, 0xD8, 0x04, 0x01,
	0x29, 0x02, 0x02, 0x06, 0x0C, 0x01, 0x01, 0xDD, 0x01, 0x01, 0xDD, 0x84,
	0x30, 0x01, 0x08, 0x09, 0xDF, 0x02, 0x03, 0x2A, 0x06, 0x11, 0x01, 0x10,
	0xDD, 0x01, 0x04, 0x09, 0x2A, 0xDD, 0x62, 0x2A, 0xDD, 0x60, 0x83, 0x47,
	0xD8, 0x04, 0x01, 0x29, 0x04, 0x01, 0x29, 0x00, 0x00, 0x01, 0x0E, 0xDF,
	0x01, 0x00, 0xDE, 0x00, 0x03, 0x76, 0x2E, 0xC9, 0x05, 0x01, 0x00, 0x7C,
	0x2F, 0x2A, 0x01, 0x82, 0x80, 0x80, 0x80, 0x00, 0x13, 0x06, 0x05, 0x29,
	0x01, 0x1D, 0x04, 0x0E, 0x2A, 0x01, 0x83, 0xC0, 0x80, 0x80, 0x00, 0x13,
	0x2A, 0x06, 0x01, 0x47, 0x29, 0xA3, 0x03, 0x00, 0x02, 0x00, 0x25, 0x2A,
	0x5B, 0x06, 0x02, 0x37, 0x2B, 0x03, 0x01, 0x93, 0x2E, 0x01, 0x86, 0x03,
	0x11, 0x03, 0x02, 0x01, 0x0C, 0xDF, 0x02, 0x01, 0x7E, 0x30, 0x08, 0x02,
	0x02, 0x01, 0x02, 0x13, 0x08, 0x01, 0x06, 0x08, 0xDE, 0x01, 0x03, 0xDF,
	0x02, 0x00, 0xDD, 0x7D, 0x7E, 0x30, 0xD8, 0x02, 0x02, 0x06, 0x1C, 0x90,
	0x2E, 0x2A, 0x01, 0x83, 0xFE, 0x00, 0x0B, 0x06, 0x03, 0xDD, 0x04, 0x0F,
	0x01, 0x81, 0x7F, 0x13, 0xDF, 0x76, 0x2E, 0xCA, 0x01, 0x01, 0x0C, 0x01,
	0x03, 0x08, 0xDF, 0x02, 0x01, 0xDD, 0x83, 0x02, 0x01, 0xD7, 0x00, 0x00,
	0x54, 0x2A, 0x01, 0x00, 0x0F, 0x06, 0x02, 0x63, 0x00, 0xCC, 0x29, 0x04,
	0x73, 0x00, 0x2A, 0xDF, 0xD7, 0x00, 0x00, 0x01, 0x00, 0x76, 0x2E, 0xC8,
	0x06, 0x0C, 0x61, 0x3A, 0x06, 0x08, 0x01, 0x80, 0x41, 0xDF, 0x01, 0x80,
	0x42, 0xDF, 0x46, 0x06, 0x07, 0x5F, 0x3A, 0x06, 0x03, 0x01, 0x01, 0xDF,
	0x45, 0x06, 0x08, 0x5F, 0x3A, 0x06, 0x04, 0x01, 0x80, 0x40, 0xDF, 0x47,
	0x29, 0x00, 0x01, 0x01, 0x00, 0x03, 0x00, 0x46, 0x45, 0x39, 0x05, 0x14,
	0x01, 0x01, 0x01, 0x80, 0x7C, 0xDB, 0x03, 0x00, 0x01, 0x03, 0x01, 0x80,
	0x7C, 0xDB, 0x02, 0x00, 0x08, 0x47, 0x29, 0x00, 0x46, 0x06, 0x07, 0x01,
	0x01, 0x44, 0x29, 0xDB, 0x03, 0x00, 0x45, 0x06, 0x0A, 0x01, 0x03, 0x44,
	0x29, 0xDB, 0x02, 0x00, 0x08, 0x03, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x04, 0xDC, 0x01, 0x05, 0xDC, 0x01, 0x06, 0xDC, 0x01,
	0x03, 0xDC, 0x01, 0x02, 0xDC, 0x0A, 0x63, 0x00, 0x01, 0x03, 0x00, 0x3A,
	0x01, 0x01, 0x02, 0x00, 0x0C, 0x13, 0x05, 0x01, 0x00, 0x61, 0x01, 0x03,
	0x3B, 0x06, 0x07, 0x02, 0x00, 0xDF, 0x01, 0x02, 0x3B, 0xDF, 0x00, 0x00,
	0x2A, 0x01, 0x08, 0x52, 0xDF, 0xDF, 0x00, 0x00, 0x2A, 0x01, 0x10, 0x52,
	0xDF, 0xDD, 0x00, 0x00, 0x2A, 0x55, 0x06, 0x02, 0x29, 0x00, 0xCC, 0x29,
	0x04, 0x76
};

 inline static const uint16_t _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_caddr[] = {
	0,
	5,
	10,
	15,
	20,
	25,
	30,
	35,
	40,
	44,
	48,
	52,
	56,
	60,
	64,
	68,
	72,
	76,
	80,
	84,
	88,
	92,
	96,
	100,
	104,
	109,
	114,
	119,
	124,
	129,
	134,
	139,
	144,
	149,
	154,
	159,
	164,
	169,
	174,
	180,
	185,
	190,
	195,
	200,
	205,
	210,
	215,
	220,
	225,
	230,
	235,
	240,
	245,
	250,
	255,
	260,
	265,
	270,
	275,
	280,
	285,
	290,
	299,
	303,
	328,
	334,
	353,
	364,
	398,
	509,
	513,
	546,
	556,
	580,
	648,
	662,
	668,
	727,
	746,
	768,
	817,
	866,
	942,
	1044,
	1055,
	1641,
	1645,
	1712,
	1722,
	1753,
	1777,
	1823,
	1893,
	1933,
	1947,
	1956,
	1960,
	2055,
	2063,
	2099,
	2110,
	2126,
	2132,
	2143,
	2178,
	2204,
	2216,
	2222,
	2237,
	2393,
	2402,
	2415,
	2424,
	2431,
	2534,
	2555,
	2568,
	2584,
	2602,
	2634,
	2707,
	2720,
	2901,
	2909,
	3036,
	3050,
	3055,
	3099,
	3156,
	3177,
	3204,
	3212,
	3220
};

#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INTERPRETED   91

#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_ENTER(ip, rp, slot)   do { \
		const unsigned char *t0_newip; \
		uint32_t t0_lnum; \
		t0_newip = &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_codeblock[_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_caddr[(slot) - _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INTERPRETED]]; \
		t0_lnum = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_unsigned(&t0_newip); \
		(rp) += t0_lnum; \
		*((rp) ++) = (uint32_t)((ip) - &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_codeblock[0]) + (t0_lnum << 16); \
		(ip) = t0_newip; \
	} while (0)

#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_DEFENTRY(name, slot) \
void \
name(void *ctx) \
{ \
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *t0ctx = (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)ctx; \
	t0ctx->ip = &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_codeblock[0]; \
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_ENTER(t0ctx->ip, t0ctx->rp, slot); \
}

_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_DEFENTRY(br_ssl_hs_server_init_main, 164)

#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_NEXT(t0ipp)   (*(*(t0ipp)) ++)

 inline void
br_ssl_hs_server_run(void *t0ctx)
{
	uint32_t *dp, *rp;
	const unsigned char *ip;

#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_LOCAL(x)    (*(rp - 2 - (x)))
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP()       (*-- dp)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi()      (*(int32_t *)(-- dp))
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PEEK(x)     (*(dp - 1 - (x)))
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PEEKi(x)    (*(int32_t *)(dp - 1 - (x)))
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(v)     do { *dp = (v); dp ++; } while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(v)    do { *(int32_t *)dp = (v); dp ++; } while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RPOP()      (*-- rp)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RPOPi()     (*(int32_t *)(-- rp))
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RPUSH(v)    do { *rp = (v); rp ++; } while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RPUSHi(v)   do { *(int32_t *)rp = (v); rp ++; } while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_ROLL(x)     do { \
	size_t t0len = (size_t)(x); \
	uint32_t t0tmp = *(dp - 1 - t0len); \
	memmove(dp - t0len - 1, dp - t0len, t0len * sizeof *dp); \
	*(dp - 1) = t0tmp; \
} while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_SWAP()      do { \
	uint32_t t0tmp = *(dp - 2); \
	*(dp - 2) = *(dp - 1); \
	*(dp - 1) = t0tmp; \
} while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_ROT()       do { \
	uint32_t t0tmp = *(dp - 3); \
	*(dp - 3) = *(dp - 2); \
	*(dp - 2) = *(dp - 1); \
	*(dp - 1) = t0tmp; \
} while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_NROT()       do { \
	uint32_t t0tmp = *(dp - 1); \
	*(dp - 1) = *(dp - 2); \
	*(dp - 2) = *(dp - 3); \
	*(dp - 3) = t0tmp; \
} while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PICK(x)      do { \
	uint32_t t0depth = (x); \
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PEEK(t0depth)); \
} while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_CO()         do { \
	goto t0_exit; \
} while (0)
#define _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RET()        goto t0_next

	dp = ((_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)t0ctx)->dp;
	rp = ((_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)t0ctx)->rp;
	ip = ((_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)t0ctx)->ip;
	goto t0_next;
	for (;;) {
		uint32_t t0x;

	t0_next:
		t0x = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_NEXT(&ip);
		if (t0x < _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_INTERPRETED) {
			switch (t0x) {
				int32_t t0off;

			case 0: /* ret */
				t0x = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RPOP();
				rp -= (t0x >> 16);
				t0x &= 0xFFFF;
				if (t0x == 0) {
					ip = NULL;
					goto t0_exit;
				}
				ip = &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_codeblock[t0x];
				break;
			case 1: /* literal constant */
				_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_signed(&ip));
				break;
			case 2: /* read local */
				_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_LOCAL(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_unsigned(&ip)));
				break;
			case 3: /* write local */
				_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_LOCAL(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_unsigned(&ip)) = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
				break;
			case 4: /* jump */
				t0off = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_signed(&ip);
				ip += t0off;
				break;
			case 5: /* jump if */
				t0off = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_signed(&ip);
				if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP()) {
					ip += t0off;
				}
				break;
			case 6: /* jump if not */
				t0off = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_parse7E_signed(&ip);
				if (!_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP()) {
					ip += t0off;
				}
				break;
			case 7: {
				/* * */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(a * b);

				}
				break;
			case 8: {
				/* + */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(a + b);

				}
				break;
			case 9: {
				/* - */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(a - b);

				}
				break;
			case 10: {
				/* -rot */
 _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_NROT(); 
				}
				break;
			case 11: {
				/* < */

	int32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	int32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a < b));

				}
				break;
			case 12: {
				/* << */

	int c = (int)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	uint32_t x = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(x << c);

				}
				break;
			case 13: {
				/* <= */

	int32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	int32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a <= b));

				}
				break;
			case 14: {
				/* <> */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a != b));

				}
				break;
			case 15: {
				/* = */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a == b));

				}
				break;
			case 16: {
				/* > */

	int32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	int32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a > b));

				}
				break;
			case 17: {
				/* >= */

	int32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	int32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a >= b));

				}
				break;
			case 18: {
				/* >> */

	int c = (int)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	int32_t x = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(x >> c);

				}
				break;
			case 19: {
				/* and */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(a & b);

				}
				break;
			case 20: {
				/* begin-cert */

	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain_len == 0) {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);
	} else {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_cur = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain->data;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain->data_len;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain ++;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain_len --;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_len);
	}

				}
				break;
			case 21: {
				/* begin-ta-name */

	const br_x500_name *dn;
	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_index >= _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->num_tas) {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);
	} else {
		if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->ta_names == NULL) {
			dn = &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->tas[_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_index].dn;
		} else {
			dn = &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->ta_names[_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_index];
		}
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_index ++;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn = dn->data;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_len = dn->len;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_len);
	}

				}
				break;
			case 22: {
				/* begin-ta-name-list */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_index = 0;

				}
				break;
			case 23: {
				/* bzero */

	size_t len = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	void *addr = (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	memset(addr, 0, len);

				}
				break;
			case 24: {
				/* call-policy-handler */

	int x;
	br_ssl_server_choices choices;

	x = (*_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->policy_vtable)->choose(
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->policy_vtable, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, &choices);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session.cipher_suite = choices.cipher_suite;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->sign_hash_id = choices.algo_id;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain = choices.chain;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain_len = choices.chain_len;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-(x != 0));

				}
				break;
			case 25: {
				/* can-output? */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out > 0));

				}
				break;
			case 26: {
				/* check-resume */

	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session.session_id_len == 32
		&& _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cache_vtable != NULL && (*_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cache_vtable)->load(
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cache_vtable, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session))
	{
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);
	} else {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(0);
	}

				}
				break;
			case 27: {
				/* co */
 _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_CO(); 
				}
				break;
			case 28: {
				/* compute-Finished-inner */

	int prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	int from_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	unsigned char seed[48];
	size_t seed_len;

	br_tls_prf_impl prf = br_ssl_engine_get_PRF(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, prf_id);
	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session.version >= BR_TLS12) {
		seed_len = br_multihash_out(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, prf_id, seed);
	} else {
		br_multihash_out(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, br_md5_ID, seed);
		br_multihash_out(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, br_sha1_ID, seed + 16);
		seed_len = 36;
	}
	prf(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, 12, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session.master_secret,
		sizeof _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session.master_secret,
		from_client ? "client finished" : "server finished",
		seed, seed_len);

				}
				break;
			case 29: {
				/* compute-hash-CV */

	int i;

	for (i = 1; i <= 6; i ++) {
		br_multihash_out(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, i,
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad + _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_PAD_OFF[i - 1]);
	}

				}
				break;
			case 30: {
				/* copy-cert-chunk */

	size_t clen;

	clen = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_len;
	if (clen > sizeof _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad) {
		clen = sizeof _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad;
	}
	memcpy(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_cur, clen);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_cur += clen;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->cert_len -= clen;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(clen);

				}
				break;
			case 31: {
				/* copy-dn-chunk */

	size_t clen;

	clen = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_len;
	if (clen > sizeof _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad) {
		clen = sizeof _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad;
	}
	memcpy(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn, clen);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn += clen;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cur_dn_len -= clen;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(clen);

				}
				break;
			case 32: {
				/* copy-hash-CV */

	int id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	size_t off, len;

	if (id == 0) {
		off = 0;
		len = 36;
	} else {
		if (br_multihash_getimpl(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, id) == 0) {
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(0);
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RET();
		}
		off = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_PAD_OFF[id - 1];
		len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_HASH_PAD_OFF[id] - off;
	}
	memcpy(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->hash_CV, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad + off, len);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->hash_CV_len = len;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->hash_CV_id = id;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);

				}
				break;
			case 33: {
				/* copy-protocol-name */

	size_t idx = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	size_t len = strlen(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->protocol_names[idx]);
	memcpy(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->protocol_names[idx], len);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(len);

				}
				break;
			case 34: {
				/* data-get8 */

	size_t addr = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_datablock[addr]);

				}
				break;
			case 35: {
				/* discard-input */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in = 0;

				}
				break;
			case 36: {
				/* do-ecdh */

	int prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	size_t len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdh(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, prf_id, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, len);

				}
				break;
			case 37: {
				/* do-ecdhe-part1 */

	int curve = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdhe_part1(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, curve));

				}
				break;
			case 38: {
				/* do-ecdhe-part2 */

	int prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	size_t len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_ecdhe_part2(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, prf_id, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, len);

				}
				break;
			case 39: {
				/* do-rsa-decrypt */

	int prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	size_t len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_rsa_decrypt(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, prf_id, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, len);

				}
				break;
			case 40: {
				/* do-static-ecdh */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_do_static_ecdh(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP());

				}
				break;
			case 41: {
				/* drop */
 (void)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP(); 
				}
				break;
			case 42: {
				/* dup */
 _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PEEK(0)); 
				}
				break;
			case 43: {
				/* fail */

	br_ssl_engine_fail(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, (int)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi());
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_CO();

				}
				break;
			case 44: {
				/* flush-record */

	br_ssl_engine_flush_record(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG);

				}
				break;
			case 45: {
				/* get-key-type-usages */

	const br_x509_class *xc;
	const br_x509_pkey *pk;
	unsigned usages;

	xc = *(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);
	pk = xc->get_pkey(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx, &usages);
	if (pk == NULL) {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(0);
	} else {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(pk->key_type | usages);
	}

				}
				break;
			case 46: {
				/* get16 */

	size_t addr = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(*(uint16_t *)((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr));

				}
				break;
			case 47: {
				/* get32 */

	size_t addr = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(*(uint32_t *)((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr));

				}
				break;
			case 48: {
				/* get8 */

	size_t addr = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(*((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr));

				}
				break;
			case 49: {
				/* has-input? */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in != 0));

				}
				break;
			case 50: {
				/* memcmp */

	size_t len = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	void *addr2 = (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	void *addr1 = (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	int x = memcmp(addr1, addr2, len);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH((uint32_t)-(x == 0));

				}
				break;
			case 51: {
				/* memcpy */

	size_t len = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	void *src = (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	void *dst = (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	memcpy(dst, src, len);

				}
				break;
			case 52: {
				/* mkrand */

	size_t len = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	void *addr = (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_hmac_drbg_generate(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->rng, addr, len);

				}
				break;
			case 53: {
				/* more-incoming-bytes? */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in != 0 || !br_ssl_engine_recvrec_finished(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG));

				}
				break;
			case 54: {
				/* multihash-init */

	br_multihash_init(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash);

				}
				break;
			case 55: {
				/* neg */

	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-a);

				}
				break;
			case 56: {
				/* not */

	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(~a);

				}
				break;
			case 57: {
				/* or */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(a | b);

				}
				break;
			case 58: {
				/* over */
 _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PEEK(1)); 
				}
				break;
			case 59: {
				/* pick */
 _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PICK(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP()); 
				}
				break;
			case 60: {
				/* read-chunk-native */

	size_t clen = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in;
	if (clen > 0) {
		uint32_t addr, len;

		len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
		addr = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
		if ((size_t)len < clen) {
			clen = (size_t)len;
		}
		memcpy((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_in, clen);
		if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->record_type_in == BR_SSL_HANDSHAKE) {
			br_multihash_update(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_in, clen);
		}
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(addr + (uint32_t)clen);
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(len - (uint32_t)clen);
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_in += clen;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in -= clen;
	}

				}
				break;
			case 61: {
				/* read8-native */

	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in > 0) {
		unsigned char x;

		x = *_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_in ++;
		if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->record_type_in == BR_SSL_HANDSHAKE) {
			br_multihash_update(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, &x, 1);
		}
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(x);
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_in --;
	} else {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);
	}

				}
				break;
			case 62: {
				/* save-session */

	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cache_vtable != NULL) {
		(*_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cache_vtable)->save(
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->cache_vtable, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, &_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->session);
	}

				}
				break;
			case 63: {
				/* set-max-frag-len */

	size_t max_frag_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();

	br_ssl_engine_new_max_frag_len(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, max_frag_len);

	/*
	 * We must adjust our own output limit. Since we call this only
	 * after receiving a ClientHello and before beginning to send
	 * the ServerHello, the next output record should be empty at
	 * that point, so we can use max_frag_len as a limit.
	 */
	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out > max_frag_len) {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out = max_frag_len;
	}

				}
				break;
			case 64: {
				/* set16 */

	size_t addr = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	*(uint16_t *)((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr) = (uint16_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();

				}
				break;
			case 65: {
				/* set32 */

	size_t addr = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	*(uint32_t *)((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr) = (uint32_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();

				}
				break;
			case 66: {
				/* set8 */

	size_t addr = (size_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	*((unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr) = (unsigned char)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();

				}
				break;
			case 67: {
				/* supported-curves */

	uint32_t x = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iec == NULL ? 0 : _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iec->supported_curves;
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(x);

				}
				break;
			case 68: {
				/* supported-hash-functions */

	int i;
	unsigned x, num;

	x = 0;
	num = 0;
	for (i = br_sha1_ID; i <= br_sha512_ID; i ++) {
		if (br_multihash_getimpl(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, i)) {
			x |= 1U << i;
			num ++;
		}
	}
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(x);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(num);

				}
				break;
			case 69: {
				/* supports-ecdsa? */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iecdsa != 0));

				}
				break;
			case 70: {
				/* supports-rsa-sign? */

	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->irsavrfy != 0));

				}
				break;
			case 71: {
				/* swap */
 _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_SWAP(); 
				}
				break;
			case 72: {
				/* switch-aesgcm-in */

	int is_client, prf_id;
	unsigned cipher_key_len;

	cipher_key_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	is_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_ssl_engine_switch_gcm_in(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, is_client, prf_id,
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iaes_ctr, cipher_key_len);

				}
				break;
			case 73: {
				/* switch-aesgcm-out */

	int is_client, prf_id;
	unsigned cipher_key_len;

	cipher_key_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	is_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_ssl_engine_switch_gcm_out(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, is_client, prf_id,
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iaes_ctr, cipher_key_len);

				}
				break;
			case 74: {
				/* switch-cbc-in */

	int is_client, prf_id, mac_id, aes;
	unsigned cipher_key_len;

	cipher_key_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	aes = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	mac_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	is_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_ssl_engine_switch_cbc_in(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, is_client, prf_id, mac_id,
		aes ? _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iaes_cbcdec : _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->ides_cbcdec, cipher_key_len);

				}
				break;
			case 75: {
				/* switch-cbc-out */

	int is_client, prf_id, mac_id, aes;
	unsigned cipher_key_len;

	cipher_key_len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	aes = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	mac_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	is_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_ssl_engine_switch_cbc_out(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, is_client, prf_id, mac_id,
		aes ? _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->iaes_cbcenc : _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->ides_cbcenc, cipher_key_len);

				}
				break;
			case 76: {
				/* switch-chapol-in */

	int is_client, prf_id;

	prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	is_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_ssl_engine_switch_chapol_in(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, is_client, prf_id);

				}
				break;
			case 77: {
				/* switch-chapol-out */

	int is_client, prf_id;

	prf_id = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	is_client = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	br_ssl_engine_switch_chapol_out(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG, is_client, prf_id);

				}
				break;
			case 78: {
				/* ta-names-total-length */

	size_t u, len;

	len = 0;
	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->ta_names != NULL) {
		for (u = 0; u < _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->num_tas; u ++) {
			len += _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->ta_names[u].len + 2;
		}
	} else if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->tas != NULL) {
		for (u = 0; u < _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->num_tas; u ++) {
			len += _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX->tas[u].dn.len + 2;
		}
	}
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(len);

				}
				break;
			case 79: {
				/* test-protocol-name */

	size_t len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	size_t u;

	for (u = 0; u < _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->protocol_names_num; u ++) {
		const char *name;

		name = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->protocol_names[u];
		if (len == strlen(name) && memcmp(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, name, len) == 0) {
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(u);
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_RET();
		}
	}
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);

				}
				break;
			case 80: {
				/* total-chain-length */

	size_t u;
	uint32_t total;

	total = 0;
	for (u = 0; u < _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain_len; u ++) {
		total += 3 + (uint32_t)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->chain[u].data_len;
	}
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(total);

				}
				break;
			case 81: {
				/* u< */

	uint32_t b = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	uint32_t a = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(-(uint32_t)(a < b));

				}
				break;
			case 82: {
				/* u>> */

	int c = (int)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POPi();
	uint32_t x = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(x >> c);

				}
				break;
			case 83: {
				/* verify-CV-sig */

	int err;

	err = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_verify_CV_sig(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_CTX, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP());
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(err);

				}
				break;
			case 84: {
				/* write-blob-chunk */

	size_t clen = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out;
	if (clen > 0) {
		uint32_t addr, len;

		len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
		addr = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
		if ((size_t)len < clen) {
			clen = (size_t)len;
		}
		memcpy(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_out, (unsigned char *)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG + addr, clen);
		if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->record_type_out == BR_SSL_HANDSHAKE) {
			br_multihash_update(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_out, clen);
		}
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(addr + (uint32_t)clen);
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(len - (uint32_t)clen);
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_out += clen;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out -= clen;
	}

				}
				break;
			case 85: {
				/* write8-native */

	unsigned char x;

	x = (unsigned char)_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out > 0) {
		if (_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->record_type_out == BR_SSL_HANDSHAKE) {
			br_multihash_update(&_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->mhash, &x, 1);
		}
		*_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hbuf_out ++ = x;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->hlen_out --;
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(-1);
	} else {
		_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSHi(0);
	}

				}
				break;
			case 86: {
				/* x509-append */

	const br_x509_class *xc;
	size_t len;

	xc = *(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);
	len = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	xc->append(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->pad, len);

				}
				break;
			case 87: {
				/* x509-end-cert */

	const br_x509_class *xc;

	xc = *(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);
	xc->end_cert(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);

				}
				break;
			case 88: {
				/* x509-end-chain */

	const br_x509_class *xc;

	xc = *(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);
	_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_PUSH(xc->end_chain(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx));

				}
				break;
			case 89: {
				/* x509-start-cert */

	const br_x509_class *xc;

	xc = *(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);
	xc->start_cert(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx, _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP());

				}
				break;
			case 90: {
				/* x509-start-chain */

	const br_x509_class *xc;
	uint32_t bc;

	bc = _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_POP();
	xc = *(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx);
	xc->start_chain(_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->x509ctx, bc ? _opt_libs_BearSSL_src_ssl_ssl_hs_server_c_ENG->server_name : NULL);

				}
				break;
			}

		} else {
			_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_T0_ENTER(ip, rp, t0x);
		}
	}
t0_exit:
	((_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)t0ctx)->dp = dp;
	((_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)t0ctx)->rp = rp;
	((_opt_libs_BearSSL_src_ssl_ssl_hs_server_c_t0_context *)t0ctx)->ip = ip;
}
#endif
