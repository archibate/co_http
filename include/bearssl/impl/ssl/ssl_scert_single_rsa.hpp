#ifndef BEARSSL_IMPL_SSL_SSL_SCERT_SINGLE_RSA_HPP
#define BEARSSL_IMPL_SSL_SSL_SCERT_SINGLE_RSA_HPP

/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"

 inline  int
_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_choose(const br_ssl_server_policy_class **pctx,
	const br_ssl_server_context *cc,
	br_ssl_server_choices *choices)
{
	br_ssl_server_policy_rsa_context *pc;
	const br_suite_translated *st;
	size_t u, st_num;
	unsigned hash_id;

	pc = (br_ssl_server_policy_rsa_context *)pctx;
	st = br_ssl_server_get_client_suites(cc, &st_num);
	hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc));
	if (cc->eng.session.version < BR_TLS12) {
		hash_id = 0;
	}
	choices->chain = pc->chain;
	choices->chain_len = pc->chain_len;
	for (u = 0; u < st_num; u ++) {
		unsigned tt;

		tt = st[u][1];
		switch (tt >> 12) {
		case BR_SSLKEYX_RSA:
			if ((pc->allowed_usages & BR_KEYTYPE_KEYX) != 0) {
				choices->cipher_suite = st[u][0];
				return 1;
			}
			break;
		case BR_SSLKEYX_ECDHE_RSA:
			if ((pc->allowed_usages & BR_KEYTYPE_SIGN) != 0
				&& hash_id != 0)
			{
				choices->cipher_suite = st[u][0];
				choices->algo_id = hash_id + 0xFF00;
				return 1;
			}
			break;
		}
	}
	return 0;
}

 inline  uint32_t
_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_do_keyx(const br_ssl_server_policy_class **pctx,
	unsigned char *data, size_t *len)
{
	br_ssl_server_policy_rsa_context *pc;

	pc = (br_ssl_server_policy_rsa_context *)pctx;
	return br_rsa_ssl_decrypt(pc->irsacore, pc->sk, data, *len);
}

/*
 * OID for hash functions in RSA signatures.
 */
 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA1[] = {
	0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA224[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA256[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA384[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};

 inline static const unsigned char _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA512[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

 inline static const unsigned char *_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID[] = {
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA1,
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA224,
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA256,
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA384,
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID_SHA512
};

 inline  size_t
_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_do_sign(const br_ssl_server_policy_class **pctx,
	unsigned algo_id, unsigned char *data, size_t hv_len, size_t len)
{
	br_ssl_server_policy_rsa_context *pc;
	unsigned char hv[64];
	size_t sig_len;
	const unsigned char *hash_oid;

	pc = (br_ssl_server_policy_rsa_context *)pctx;
	memcpy(hv, data, hv_len);
	algo_id &= 0xFF;
	if (algo_id == 0) {
		hash_oid = NULL;
	} else if (algo_id >= 2 && algo_id <= 6) {
		hash_oid = _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_HASH_OID[algo_id - 2];
	} else {
		return 0;
	}
	sig_len = (pc->sk->n_bitlen + 7) >> 3;
	if (len < sig_len) {
		return 0;
	}
	return pc->irsasign(hash_oid, hv, hv_len, pc->sk, data) ? sig_len : 0;
}

 inline static const br_ssl_server_policy_class _opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_policy_vtable = {
	sizeof(br_ssl_server_policy_rsa_context),
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_choose,
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_do_keyx,
	_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_do_sign
};

/* see bearssl_ssl.h */
 inline void
br_ssl_server_set_single_rsa(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_rsa_private_key *sk, unsigned allowed_usages,
	br_rsa_private irsacore, br_rsa_pkcs1_sign irsasign)
{
	cc->chain_handler.single_rsa.vtable = &_opt_libs_BearSSL_src_ssl_ssl_scert_single_rsa_c_sr_policy_vtable;
	cc->chain_handler.single_rsa.chain = chain;
	cc->chain_handler.single_rsa.chain_len = chain_len;
	cc->chain_handler.single_rsa.sk = sk;
	cc->chain_handler.single_rsa.allowed_usages = allowed_usages;
	cc->chain_handler.single_rsa.irsacore = irsacore;
	cc->chain_handler.single_rsa.irsasign = irsasign;
	cc->policy_vtable = &cc->chain_handler.single_rsa.vtable;
}
#endif
