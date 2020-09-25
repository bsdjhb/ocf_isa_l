/*
 * Copyright (c) 2020 Netflix, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/counter.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/xform_auth.h>

#include <crypto/ossl/ossl.h>

#include "cryptodev_if.h"

#include <aes_cbc.h>
#include <aes_gcm.h>

struct isal_softc {
	int32_t	sc_cid;

	counter_u64_t sc_cbc_encrypt;
	counter_u64_t sc_cbc_decrypt;
	counter_u64_t sc_cbc_aligned_bytes;
	counter_u64_t sc_cbc_bounced_bytes;
	counter_u64_t sc_gcm_encrypt;
	counter_u64_t sc_gcm_decrypt;
	counter_u64_t sc_gcm_update_bytes;
	counter_u64_t sc_gcm_update_nt_bytes;
	counter_u64_t sc_gcm_update_calls;
	counter_u64_t sc_gcm_update_nt_calls;
#ifdef CSP_MODE_MTE
	counter_u64_t sc_mte_encrypt;
	counter_u64_t sc_mte_aligned_bytes;
	counter_u64_t sc_mte_bounced_bytes;
#endif
};

struct isal_cbc_session {
	void (*dec)(void *, uint8_t *, uint8_t *, void *, uint64_t);
	int (*enc)(void *, uint8_t *, uint8_t *, void *, uint64_t);

	struct cbc_key_data key_data __aligned(16);
};

struct isal_gcm_session {
	struct gcm_key_data key_data;

	void (*pre)(const void *, struct gcm_key_data *);
	void (*init)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, uint8_t const *, uint64_t);
	void (*dec_update)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*dec_update_nt)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*dec_finalize)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, uint64_t);
	void (*enc_update)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*enc_update_nt)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*enc_finalize)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, uint64_t);
};

struct isal_auth_session {
	struct auth_hash *axf;
	void *ictx;
	void *octx;
	u_int mlen;
};

struct isal_session {
	int	(*process)(struct isal_softc *, struct cryptop *,
		    struct isal_session *);
	union {
		struct isal_cbc_session cbc;
		struct isal_gcm_session gcm;
	};
	struct isal_auth_session auth;
};

static int isal_process_cbc(struct isal_softc *, struct cryptop *,
    struct isal_session *);
static int isal_process_gcm(struct isal_softc *, struct cryptop *,
    struct isal_session *);
#ifdef CSP_MODE_MTE
static int isal_process_mte(struct isal_softc *, struct cryptop *,
    struct isal_session *);
#endif

static MALLOC_DEFINE(M_ISAL, "isal", "ISA-L crypto");

/* Base AES routines all require AESNI and SSE4.1. */
static bool
cpu_supported(void)
{
	return ((cpu_feature2 & (CPUID2_SSE41 | CPUID2_AESNI)) ==
	    (CPUID2_SSE41 | CPUID2_AESNI));
}

static void
isal_identify(driver_t *driver, device_t parent)
{

	if (cpu_supported() && device_find_child(parent, "isal", -1) == NULL)
		BUS_ADD_CHILD(parent, 10, "isal", -1);
}

static int
isal_probe(device_t dev)
{

	device_set_desc(dev, "ISA-L crypto");
	return (BUS_PROBE_DEFAULT);
}

static void
isal_sysctls(device_t dev, struct isal_softc *sc)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *children;

	ctx = device_get_sysctl_ctx(dev);

	oid = device_get_sysctl_tree(dev);
	children = SYSCTL_CHILDREN(oid);

	oid = SYSCTL_ADD_NODE(ctx, children, OID_AUTO, "stats",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "statistics");
	children = SYSCTL_CHILDREN(oid);

	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "cbc_encrypt",
	    CTLFLAG_RD, &sc->sc_cbc_encrypt,
	    "AES-CBC encryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "cbc_decrypt",
	    CTLFLAG_RD, &sc->sc_cbc_decrypt,
	    "AES-CBC decryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "cbc_aligned_bytes",
	    CTLFLAG_RD, &sc->sc_cbc_aligned_bytes,
	    "Bytes encrypted/decrypted by AES-CBC without bouncing");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "cbc_bounced_bytes",
	    CTLFLAG_RD, &sc->sc_cbc_bounced_bytes,
	    "Bytes encrypted/decrypted by AES-CBC with bouncing");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_encrypt",
	    CTLFLAG_RD, &sc->sc_gcm_encrypt,
	    "AES-GCM encryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_decrypt",
	    CTLFLAG_RD, &sc->sc_gcm_decrypt,
	    "AES-GCM decryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_bytes",
	    CTLFLAG_RD, &sc->sc_gcm_update_bytes,
	    "Bytes encrypted/decrypted by regular AES-GCM update");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_nt_bytes",
	    CTLFLAG_RD, &sc->sc_gcm_update_nt_bytes,
	    "Bytes encrypted/decrypted by non-temporal AES-GCM update");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_calls",
	    CTLFLAG_RD, &sc->sc_gcm_update_calls,
	    "Calls to regular AES-GCM update functions");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_nt_calls",
	    CTLFLAG_RD, &sc->sc_gcm_update_nt_calls,
	    "Calls to non-temporal AES-GCM update functions");
#ifdef CSP_MODE_MTE
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "mte_encrypt",
	    CTLFLAG_RD, &sc->sc_mte_encrypt,
	    "AES-CBC MtE encryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "mte_aligned_bytes",
	    CTLFLAG_RD, &sc->sc_mte_aligned_bytes,
	    "Bytes encrypted by AES-CBC MtE without bouncing");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "mte_bounced_bytes",
	    CTLFLAG_RD, &sc->sc_mte_bounced_bytes,
	    "Bytes encrypted by AES-CBC MtE with bouncing");
#endif
}

static int
isal_attach(device_t dev)
{
	struct isal_softc *sc;

	sc = device_get_softc(dev);

	sc->sc_cid = crypto_get_driverid(dev, sizeof(struct isal_session),
	    CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC |
	    CRYPTOCAP_F_ACCEL_SOFTWARE);
	if (sc->sc_cid < 0) {
		device_printf(dev, "failed to allocate crypto driver id\n");
		return (ENXIO);
	}

	sc->sc_cbc_encrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_cbc_decrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_cbc_aligned_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_cbc_bounced_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_encrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_decrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_nt_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_calls = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_nt_calls = counter_u64_alloc(M_WAITOK);
#ifdef CSP_MODE_MTE
	sc->sc_mte_encrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_mte_aligned_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_mte_bounced_bytes = counter_u64_alloc(M_WAITOK);
#endif

	isal_sysctls(dev, sc);
	return (0);
}

static int
isal_detach(device_t dev)
{
	struct isal_softc *sc;

	sc = device_get_softc(dev);

	crypto_unregister_all(sc->sc_cid);

	counter_u64_free(sc->sc_cbc_encrypt);
	counter_u64_free(sc->sc_cbc_decrypt);
	counter_u64_free(sc->sc_cbc_aligned_bytes);
	counter_u64_free(sc->sc_cbc_bounced_bytes);
	counter_u64_free(sc->sc_gcm_encrypt);
	counter_u64_free(sc->sc_gcm_decrypt);
	counter_u64_free(sc->sc_gcm_update_bytes);
	counter_u64_free(sc->sc_gcm_update_nt_bytes);
	counter_u64_free(sc->sc_gcm_update_calls);
	counter_u64_free(sc->sc_gcm_update_nt_calls);
#ifdef CSP_MODE_MTE
	counter_u64_free(sc->sc_mte_encrypt);
	counter_u64_free(sc->sc_mte_aligned_bytes);
	counter_u64_free(sc->sc_mte_bounced_bytes);
#endif
	return (0);
}

static int
isal_probesession(device_t dev, const struct crypto_session_params *csp)
{

	if ((csp->csp_flags & ~(CSP_F_SEPARATE_OUTPUT | CSP_F_SEPARATE_AAD)) !=
	    0)
		return (EINVAL);
	switch (csp->csp_mode) {
	case CSP_MODE_CIPHER:
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_CBC:
			if (csp->csp_ivlen != 16)
				return (EINVAL);
			if (csp->csp_cipher_klen != 16 &&
			    csp->csp_cipher_klen != 24 &&
			    csp->csp_cipher_klen != 32)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		break;
	case CSP_MODE_AEAD:
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_NIST_GCM_16:
			if (csp->csp_auth_mlen != 0 &&
			    csp->csp_auth_mlen != 16)
				return (EINVAL);
			if (csp->csp_ivlen != 12)
				return (EINVAL);
			if (csp->csp_cipher_klen != 16 &&
			    csp->csp_cipher_klen != 32)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		break;
#ifdef CSP_MODE_MTE
	case CSP_MODE_MTE:
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_CBC:
			if (csp->csp_ivlen != 16)
				return (EINVAL);
			if (csp->csp_cipher_klen != 16 &&
			    csp->csp_cipher_klen != 24 &&
			    csp->csp_cipher_klen != 32)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		switch (csp->csp_auth_alg) {
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
			break;
		default:
			return (EINVAL);
		}
		break;
#endif
	default:
		return (EINVAL);
	}

	/* Prefer to aesni(4). */
	return (CRYPTODEV_PROBE_ACCEL_SOFTWARE + 10);
}

static struct auth_hash *
isal_auth_hash(const struct crypto_session_params *csp)
{
	switch (csp->csp_auth_alg) {
	case CRYPTO_SHA1_HMAC:
		return (&ossl_hash_sha1);
	case CRYPTO_SHA2_256_HMAC:
		return (&ossl_hash_sha256);
	case CRYPTO_SHA2_384_HMAC:
		return (&ossl_hash_sha384);
	default:
		__assert_unreachable();
	}
}

static void
isal_auth_setkey(const struct crypto_session_params *csp,
    struct isal_auth_session *auth, const void *key)
{
	hmac_init_ipad(auth->axf, key, csp->csp_auth_klen, auth->ictx);
	hmac_init_opad(auth->axf, key, csp->csp_auth_klen, auth->octx);
}

static int
isal_newsession_auth(const struct crypto_session_params *csp,
    struct isal_auth_session *auth)
{
	auth->axf = isal_auth_hash(csp);
	auth->ictx = malloc(auth->axf->ctxsize, M_ISAL, M_NOWAIT);
	auth->octx = malloc(auth->axf->ctxsize, M_ISAL, M_NOWAIT);
	if (auth->ictx == NULL || auth->octx == NULL) {
		zfree(auth->ictx, M_ISAL);
		zfree(auth->octx, M_ISAL);
		return (ENOMEM);
	}

	if (csp->csp_auth_mlen == 0)
		auth->mlen = auth->axf->hashsize;
	else
		auth->mlen = csp->csp_auth_mlen;

	if (csp->csp_auth_key != NULL) {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		isal_auth_setkey(csp, auth, csp->csp_auth_key);
		fpu_kern_leave(curthread, NULL);
	}

	return (0);
}

static void
isal_newsession_cbc(const struct crypto_session_params *csp,
    struct isal_cbc_session *cbc)
{
	switch (csp->csp_cipher_klen) {
	case 16:
		cbc->dec = aes_cbc_dec_128;
		cbc->enc = aes_cbc_enc_128;
		break;
	case 24:
		cbc->dec = aes_cbc_dec_192;
		cbc->enc = aes_cbc_enc_192;
		break;
	case 32:
		cbc->dec = aes_cbc_dec_256;
		cbc->enc = aes_cbc_enc_256;
		break;
	default:
		__assert_unreachable();
	}

	if (csp->csp_cipher_key != NULL) {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		aes_cbc_precomp(__DECONST(void *, csp->csp_cipher_key),
		    csp->csp_cipher_klen, &cbc->key_data);
		fpu_kern_leave(curthread, NULL);
	}
}

static void
isal_newsession_gcm(const struct crypto_session_params *csp,
    struct isal_gcm_session *gcm)
{
	if (csp->csp_cipher_klen == 16) {
		gcm->pre = aes_gcm_pre_128;
		gcm->init = aes_gcm_init_128;
		gcm->dec_update = aes_gcm_dec_128_update;
		gcm->dec_update_nt = aes_gcm_dec_128_update_nt;
		gcm->dec_finalize = aes_gcm_dec_128_finalize;
		gcm->enc_update = aes_gcm_enc_128_update;
		gcm->enc_update_nt = aes_gcm_enc_128_update_nt;
		gcm->enc_finalize = aes_gcm_enc_128_finalize;
	} else {
		gcm->pre = aes_gcm_pre_256;
		gcm->init = aes_gcm_init_256;
		gcm->dec_update = aes_gcm_dec_256_update;
		gcm->dec_update_nt = aes_gcm_dec_256_update_nt;
		gcm->dec_finalize = aes_gcm_dec_256_finalize;
		gcm->enc_update = aes_gcm_enc_256_update;
		gcm->enc_update_nt = aes_gcm_enc_256_update_nt;
		gcm->enc_finalize = aes_gcm_enc_256_finalize;
	}

	if (csp->csp_cipher_key != NULL) {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		gcm->pre(csp->csp_cipher_key, &gcm->key_data);
		fpu_kern_leave(curthread, NULL);
	}
}

static int
isal_newsession(device_t dev, crypto_session_t cses,
    const struct crypto_session_params *csp)
{
	struct isal_session *s;
#ifdef CSP_MODE_MTE
	int error;
#endif

	s = crypto_get_driver_session(cses);

	switch (csp->csp_mode) {
	case CSP_MODE_CIPHER:
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_CBC:
			isal_newsession_cbc(csp, &s->cbc);
			s->process = isal_process_cbc;
			break;
		default:
			__assert_unreachable();
		}
		break;
	case CSP_MODE_AEAD:
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_NIST_GCM_16:
			isal_newsession_gcm(csp, &s->gcm);
			s->process = isal_process_gcm;
			break;
		default:
			__assert_unreachable();
		}
		break;
#ifdef CSP_MODE_MTE
	case CSP_MODE_MTE:
		isal_newsession_cbc(csp, &s->cbc);
		error = isal_newsession_auth(csp, &s->auth);
		if (error)
			return (error);
		s->process = isal_process_mte;
		break;
#endif
	default:
		__assert_unreachable();
	}

	return (0);
}

static void
isal_freesession(device_t dev, crypto_session_t cses)
{
	struct isal_session *s;

	s = crypto_get_driver_session(cses);

	zfree(s->auth.ictx, M_ISAL);
	zfree(s->auth.octx, M_ISAL);
}

static int
isal_process_cbc(struct isal_softc *sc, struct cryptop *crp,
    struct isal_session *s)
{
	struct crypto_buffer_cursor cc_in, cc_out;
	uint8_t blocks[AES_BLOCK_LEN * 4] __aligned(64);
	uint8_t iv[2][AES_BLOCK_LEN] __aligned(16);
	uint8_t *in, *out;
	size_t inlen, outlen, resid, todo;
	u_int iv_index;
	bool fpu_entered;

	if (is_fpu_kern_thread(0)) {
		fpu_entered = false;
	} else {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		fpu_entered = true;
	}

	if (crp->crp_cipher_key != NULL) {
		const struct crypto_session_params *csp;

		csp = crypto_get_params(crp->crp_session);
		aes_cbc_precomp(__DECONST(void *, crp->crp_cipher_key),
		    csp->csp_cipher_klen, &s->cbc.key_data);
	}

	iv_index = 0;
	crypto_read_iv(crp, iv[0]);

	crypto_cursor_init(&cc_in, &crp->crp_buf);
	crypto_cursor_advance(&cc_in, crp->crp_payload_start);
	resid = crp->crp_payload_length;
	if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
		crypto_cursor_init(&cc_out, &crp->crp_obuf);
		crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);
	} else
		cc_out = cc_in;

	in = crypto_cursor_segbase(&cc_in);
	inlen = crypto_cursor_seglen(&cc_in);
	out = crypto_cursor_segbase(&cc_out);
	outlen = crypto_cursor_seglen(&cc_out);
	while (resid > 0) {
		if (outlen < 16 || (uintptr_t)out % 16 != 0) {
			out = blocks;
			outlen = sizeof(blocks);
		}
		if (inlen < 16 || (uintptr_t)in % 16 != 0) {
			in = blocks;
			inlen = sizeof(blocks);
		}

		todo = MIN(rounddown2(MIN(inlen, outlen), 16), resid);
		if (in == blocks)
			crypto_cursor_copydata(&cc_in, todo, in);

		if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
			s->cbc.enc(in, iv[0], s->cbc.key_data.enc_keys, out,
			    todo);
			memcpy(iv[0], out + todo - AES_BLOCK_LEN,
			    AES_BLOCK_LEN);
		} else {
			memcpy(iv[iv_index ^ 1], in + todo - AES_BLOCK_LEN,
			    AES_BLOCK_LEN);
			s->cbc.dec(in, iv[iv_index], s->cbc.key_data.dec_keys,
			    out, todo);
			iv_index ^= 1;
		}

		if (in == blocks || out == blocks)
			counter_u64_add(sc->sc_cbc_bounced_bytes, todo);
		else
			counter_u64_add(sc->sc_cbc_aligned_bytes, todo);

		if (in == blocks) {
			in = crypto_cursor_segbase(&cc_in);
			inlen = crypto_cursor_seglen(&cc_in);
		} else {
			crypto_cursor_advance(&cc_in, todo);
			in += todo;
			inlen -= todo;
			if (inlen == 0) {
				in = crypto_cursor_segbase(&cc_in);
				inlen = crypto_cursor_seglen(&cc_in);
			}
		};

		if (out == blocks) {
			crypto_cursor_copyback(&cc_out, todo, out);
			out = crypto_cursor_segbase(&cc_out);
			outlen = crypto_cursor_seglen(&cc_out);
		} else {
			crypto_cursor_advance(&cc_out, todo);
			out += todo;
			outlen -= todo;
			if (outlen == 0) {
				out = crypto_cursor_segbase(&cc_out);
				outlen = crypto_cursor_seglen(&cc_out);
			}
		}

		resid -= todo;
	};

	if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op))
		counter_u64_add(sc->sc_cbc_encrypt, 1);
	else
		counter_u64_add(sc->sc_cbc_decrypt, 1);

	if (fpu_entered)
		fpu_kern_leave(curthread, NULL);

	explicit_bzero(iv, sizeof(iv));
	explicit_bzero(blocks, sizeof(blocks));

	return (0);
}

static int
isal_process_gcm(struct isal_softc *sc, struct cryptop *crp,
    struct isal_session *s)
{
	struct gcm_context_data context_data;
	struct crypto_buffer_cursor cc_in, cc_out;
	void *aad;
	uint8_t *in, *out;
	void (*gcm_update)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*gcm_update_nt)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	uint8_t tag[16];
	size_t inlen, outlen, resid, todo;
	int error;
	bool aad_allocated, fpu_entered;

	aad_allocated = false;
	if ((crp->crp_flags & CRYPTO_F_IV_SEPARATE) == 0)
		return (EINVAL);

	/* Setup AAD. */
	if (crp->crp_aad_length == 0)
		aad = NULL;
	else if (crp->crp_aad != NULL)
		aad = crp->crp_aad;
	else {
		aad = crypto_contiguous_subsegment(crp, crp->crp_aad_start,
		    crp->crp_aad_length);
		if (aad == NULL) {
			aad = malloc(crp->crp_aad_length, M_ISAL, M_NOWAIT);
			if (aad == NULL)
				return (ENOMEM);
			aad_allocated = true;
			crypto_copydata(crp, crp->crp_aad_start,
			    crp->crp_aad_length, aad);
		}
	}

	if (is_fpu_kern_thread(0)) {
		fpu_entered = false;
	} else {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		fpu_entered = true;
	}

	if (crp->crp_cipher_key != NULL)
		s->gcm.pre(crp->crp_cipher_key, &s->gcm.key_data);
	s->gcm.init(&s->gcm.key_data, &context_data, crp->crp_iv, aad,
	    crp->crp_aad_length);

	if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
		gcm_update = s->gcm.enc_update;
		gcm_update_nt = s->gcm.enc_update_nt;
	} else {
		gcm_update = s->gcm.dec_update;
		gcm_update_nt = s->gcm.dec_update_nt;
	}

	crypto_cursor_init(&cc_in, &crp->crp_buf);
	crypto_cursor_advance(&cc_in, crp->crp_payload_start);
	resid = crp->crp_payload_length;
	if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
		crypto_cursor_init(&cc_out, &crp->crp_obuf);
		crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);

		in = crypto_cursor_segbase(&cc_in);
		inlen = crypto_cursor_seglen(&cc_in);
		out = crypto_cursor_segbase(&cc_out);
		outlen = crypto_cursor_seglen(&cc_out);

		/*
		 * Use gcm_update_nt so long as both buffers are 16
		 * bytes aligned.
		 */
		while (resid > 0 && inlen >= 16 && outlen >= 16 &&
		    (uintptr_t)in % 16 == 0 && (uintptr_t)out % 16 == 0) {
			todo = MIN(MIN(inlen, outlen), resid);
			if (todo > 16)
				todo = rounddown2(todo, 16);

			gcm_update_nt(&s->gcm.key_data, &context_data, out, in,
			    todo);

			crypto_cursor_advance(&cc_in, todo);
			inlen -= todo;
			if (inlen == 0) {
				in = crypto_cursor_segbase(&cc_in);
				inlen = crypto_cursor_seglen(&cc_in);
			} else
				in += todo;

			crypto_cursor_advance(&cc_out, todo);
			outlen -= todo;
			if (outlen == 0) {
				out = crypto_cursor_segbase(&cc_out);
				outlen = crypto_cursor_seglen(&cc_out);
			} else
				out += todo;

			resid -= todo;
			counter_u64_add(sc->sc_gcm_update_nt_bytes, todo);
			counter_u64_add(sc->sc_gcm_update_nt_calls, 1);
		}

		/*
		 * Fallback to gcm_update once we hit any unaligned
		 * data.
		 */
		while (resid > 0) {
			todo = MIN(MIN(inlen, outlen), resid);
			
			gcm_update(&s->gcm.key_data, &context_data, out, in,
			    todo);

			crypto_cursor_advance(&cc_in, todo);
			inlen -= todo;
			if (inlen == 0) {
				in = crypto_cursor_segbase(&cc_in);
				inlen = crypto_cursor_seglen(&cc_in);
			} else
				in += todo;

			crypto_cursor_advance(&cc_out, todo);
			outlen -= todo;
			if (outlen == 0) {
				out = crypto_cursor_segbase(&cc_out);
				outlen = crypto_cursor_seglen(&cc_out);
			} else
				out += todo;

			resid -= todo;
			counter_u64_add(sc->sc_gcm_update_bytes, todo);
			counter_u64_add(sc->sc_gcm_update_calls, 1);
		}
	} else {
		while (resid > 0) {
			todo = crypto_cursor_seglen(&cc_in);
			if (todo > resid)
				todo = resid;
			in = crypto_cursor_segbase(&cc_in);
			gcm_update(&s->gcm.key_data, &context_data, in, in,
			    todo);
			crypto_cursor_advance(&cc_in, todo);
			resid -= todo;
			counter_u64_add(sc->sc_gcm_update_bytes, todo);
			counter_u64_add(sc->sc_gcm_update_calls, 1);
		}
	}

	error = 0;

	if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
		s->gcm.enc_finalize(&s->gcm.key_data, &context_data, tag,
		    sizeof(tag));
		crypto_copyback(crp, crp->crp_digest_start, sizeof(tag), tag);
		counter_u64_add(sc->sc_gcm_encrypt, 1);
	} else {
		uint8_t tag2[16];

		s->gcm.dec_finalize(&s->gcm.key_data, &context_data, tag,
		    sizeof(tag));
		crypto_copydata(crp, crp->crp_digest_start, sizeof(tag), tag2);
		if (timingsafe_bcmp(tag2, tag, 16) != 0)
			error = EBADMSG;
		counter_u64_add(sc->sc_gcm_decrypt, 1);
	}

	if (fpu_entered)
		fpu_kern_leave(curthread, NULL);

	explicit_bzero(&tag, sizeof(tag));
	explicit_bzero(&context_data, sizeof(context_data));

	if (aad_allocated)
		free(aad, M_ISAL);
	return (error);
}

#ifdef CSP_MODE_MTE
static int
isal_process_mte(struct isal_softc *sc, struct cryptop *crp,
    struct isal_session *s)
{
	struct crypto_buffer_cursor cc_in, cc_out;
	uint8_t blocks[AES_BLOCK_LEN * 4] __aligned(64);
	uint8_t iv[AES_BLOCK_LEN] __aligned(16);
	uint8_t mac[HASH_MAX_LEN];
	uint8_t *in, *out, *macp;
	size_t inlen, outlen, maclen, resid, tocopy, todo, trailer;
	struct auth_hash *axf;
	union authctx ctx;
	uint8_t pad;
	bool fpu_entered;

	if (!CRYPTO_OP_IS_ENCRYPT(crp->crp_op))
		return (EOPNOTSUPP);

	if (is_fpu_kern_thread(0)) {
		fpu_entered = false;
	} else {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		fpu_entered = true;
	}

	if (crp->crp_auth_key != NULL) {
		const struct crypto_session_params *csp;

		csp = crypto_get_params(crp->crp_session);
		isal_auth_setkey(csp, &s->auth, crp->crp_auth_key);
	}

	axf = s->auth.axf;
	memcpy(&ctx, s->auth.ictx, axf->ctxsize);

	if (crp->crp_aad != NULL)
		axf->Update(&ctx, crp->crp_aad, crp->crp_aad_length);
	else
		crypto_apply(crp, crp->crp_aad_start, crp->crp_aad_length,
		    axf->Update, &ctx);

	if (crp->crp_cipher_key != NULL) {
		const struct crypto_session_params *csp;

		csp = crypto_get_params(crp->crp_session);
		aes_cbc_precomp(__DECONST(void *, crp->crp_cipher_key),
		    csp->csp_cipher_klen, &s->cbc.key_data);
	}

	crypto_read_iv(crp, iv);

	crypto_cursor_init(&cc_in, &crp->crp_buf);
	crypto_cursor_advance(&cc_in, crp->crp_payload_start);
	resid = crp->crp_payload_length;
	if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
		crypto_cursor_init(&cc_out, &crp->crp_obuf);
		crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);
	} else
		cc_out = cc_in;

	in = crypto_cursor_segbase(&cc_in);
	inlen = crypto_cursor_seglen(&cc_in);
	out = crypto_cursor_segbase(&cc_out);
	outlen = crypto_cursor_seglen(&cc_out);
	while (resid >= AES_BLOCK_LEN) {
		if (outlen < 16 || (uintptr_t)out % 16 != 0) {
			out = blocks;
			outlen = sizeof(blocks);
		}
		if (inlen < 16 || (uintptr_t)in % 16 != 0) {
			in = blocks;
			inlen = sizeof(blocks);
		}

		todo = rounddown2(MIN(MIN(inlen, outlen), resid), 16);
		if (in == blocks)
			crypto_cursor_copydata(&cc_in, todo, in);

		axf->Update(&ctx, in, todo);
		s->cbc.enc(in, iv, s->cbc.key_data.enc_keys, out, todo);
		memcpy(iv, out + todo - AES_BLOCK_LEN, AES_BLOCK_LEN);

		if (in == blocks || out == blocks)
			counter_u64_add(sc->sc_mte_bounced_bytes, todo);
		else
			counter_u64_add(sc->sc_mte_aligned_bytes, todo);

		if (in == blocks) {
			in = crypto_cursor_segbase(&cc_in);
			inlen = crypto_cursor_seglen(&cc_in);
		} else {
			crypto_cursor_advance(&cc_in, todo);
			in += todo;
			inlen -= todo;
			if (inlen == 0) {
				in = crypto_cursor_segbase(&cc_in);
				inlen = crypto_cursor_seglen(&cc_in);
			}
		};

		if (out == blocks) {
			crypto_cursor_copyback(&cc_out, todo, out);
			out = crypto_cursor_segbase(&cc_out);
			outlen = crypto_cursor_seglen(&cc_out);
		} else {
			crypto_cursor_advance(&cc_out, todo);
			out += todo;
			outlen -= todo;
			if (outlen == 0) {
				out = crypto_cursor_segbase(&cc_out);
				outlen = crypto_cursor_seglen(&cc_out);
			}
		}

		resid -= todo;
	};

	if (resid > 0) {
		crypto_cursor_copydata(&cc_in, resid, blocks);
		axf->Update(&ctx, blocks, resid);
	}

	axf->Final(mac, &ctx);
	memcpy(&ctx, s->auth.octx, axf->ctxsize);
	axf->Update(&ctx, mac, axf->hashsize);
	axf->Final(mac, &ctx);
	macp = mac;
	maclen = s->auth.mlen;

	/*
	 * All padding bytes hold the count of additional padding
	 * bytes above the one mandatory padding byte.
	 */
	pad = crp->crp_padding_length - 1;

	trailer = maclen + crp->crp_padding_length;
	while (trailer > 0) {
		todo = min(trailer + resid, sizeof(blocks));
		tocopy = min(todo - resid, maclen);

		if (tocopy > 0) {
			memcpy(blocks + resid, macp, tocopy);
			macp += tocopy;
			maclen -= tocopy;
		}

		if (resid + tocopy < todo) {
			memset(blocks + resid + tocopy, pad, todo -
			    (resid + tocopy));
		}

		s->cbc.enc(blocks, iv, s->cbc.key_data.enc_keys, blocks, todo);
		memcpy(iv, blocks + todo - AES_BLOCK_LEN, AES_BLOCK_LEN);

		crypto_cursor_copyback(&cc_out, todo, blocks);

		trailer -= todo - resid;
		resid = 0;
	}

	counter_u64_add(sc->sc_mte_encrypt, 1);

	if (fpu_entered)
		fpu_kern_leave(curthread, NULL);

	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(mac, sizeof(mac));
	explicit_bzero(iv, sizeof(iv));
	explicit_bzero(blocks, sizeof(blocks));

	return (0);
}
#endif

static int
isal_process(device_t dev, struct cryptop *crp, int hint)
{
	struct isal_softc *sc;
	struct isal_session *s;
	int error;

	sc = device_get_softc(dev);
	s = crypto_get_driver_session(crp->crp_session);

	error = s->process(sc, crp, s);

	crp->crp_etype = error;
	crypto_done(crp);
	return (0);
}

static device_method_t isal_methods[] = {
	DEVMETHOD(device_identify,	isal_identify),
	DEVMETHOD(device_probe,		isal_probe),
	DEVMETHOD(device_attach,	isal_attach),
	DEVMETHOD(device_detach,	isal_detach),

	DEVMETHOD(cryptodev_probesession, isal_probesession),
	DEVMETHOD(cryptodev_newsession,	isal_newsession),
	DEVMETHOD(cryptodev_freesession, isal_freesession),
	DEVMETHOD(cryptodev_process,	isal_process),

	DEVMETHOD_END
};

static driver_t isal_driver = {
	"isal",
	isal_methods,
	sizeof(struct isal_softc)
};

static devclass_t isal_devclass;

DRIVER_MODULE(isal, nexus, isal_driver, isal_devclass, NULL, NULL);
MODULE_VERSION(isal, 1);
MODULE_DEPEND(isal, crypto, 1, 1, 1);
MODULE_DEPEND(isal, ossl, 1, 1, 1);
