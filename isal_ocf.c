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

#include <sys/param.h>
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

#include "cryptodev_if.h"

#include <aes_gcm.h>

#if __FreeBSD_version < 1300518 || \
    (__FreeBSD_version >= 1400000 && __FreeBSD_version < 1400017)
static __inline void *
crypto_cursor_segment(struct crypto_buffer_cursor *cc, size_t *len)
{
	*len = crypto_cursor_seglen(cc);
	return (crypto_cursor_segbase(cc));
}
#endif

struct isal_softc {
	int32_t	sc_cid;

	counter_u64_t sc_gcm_encrypt;
	counter_u64_t sc_gcm_decrypt;
	counter_u64_t sc_gcm_update_bytes;
	counter_u64_t sc_gcm_update_nt_bytes;
	counter_u64_t sc_gcm_update_calls;
	counter_u64_t sc_gcm_update_nt_calls;
};

struct isal_session {
	struct gcm_key_data key_data;

	void (*aes_gcm_pre)(const void *, struct gcm_key_data *);
	void (*aes_gcm_init)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, uint8_t const *, uint64_t);
	void (*aes_gcm_dec_update)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*aes_gcm_dec_update_nt)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*aes_gcm_dec_finalize)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, uint64_t);
	void (*aes_gcm_enc_update)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*aes_gcm_enc_update_nt)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*aes_gcm_enc_finalize)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, uint64_t);
};

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

	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_encrypt",
	    CTLFLAG_RD, &sc->sc_gcm_encrypt,
	    "AES-GCM encryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_decrypt",
	    CTLFLAG_RD, &sc->sc_gcm_decrypt,
	    "AES-GCM decryption requests completed");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_bytes",
	    CTLFLAG_RD, &sc->sc_gcm_update_bytes,
	    "Bytes encrypted/decrypted by regular update");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_nt_bytes",
	    CTLFLAG_RD, &sc->sc_gcm_update_nt_bytes,
	    "Bytes encrypted/decrypted by non-temporal update");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_calls",
	    CTLFLAG_RD, &sc->sc_gcm_update_calls,
	    "Calls to regular update functions");
	SYSCTL_ADD_COUNTER_U64(ctx, children, OID_AUTO, "gcm_update_nt_calls",
	    CTLFLAG_RD, &sc->sc_gcm_update_nt_calls,
	    "Calls to non-temporal update functions");
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

	sc->sc_gcm_encrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_decrypt = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_nt_bytes = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_calls = counter_u64_alloc(M_WAITOK);
	sc->sc_gcm_update_nt_calls = counter_u64_alloc(M_WAITOK);

	isal_sysctls(dev, sc);
	return (0);
}

static int
isal_detach(device_t dev)
{
	struct isal_softc *sc;

	sc = device_get_softc(dev);

	crypto_unregister_all(sc->sc_cid);

	counter_u64_free(sc->sc_gcm_encrypt);
	counter_u64_free(sc->sc_gcm_decrypt);
	counter_u64_free(sc->sc_gcm_update_bytes);
	counter_u64_free(sc->sc_gcm_update_nt_bytes);
	counter_u64_free(sc->sc_gcm_update_calls);
	counter_u64_free(sc->sc_gcm_update_nt_calls);
	return (0);
}

static int
isal_probesession(device_t dev, const struct crypto_session_params *csp)
{

	if ((csp->csp_flags & ~(CSP_F_SEPARATE_OUTPUT | CSP_F_SEPARATE_AAD)) !=
	    0)
		return (EINVAL);
	switch (csp->csp_mode) {
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
	default:
		return (EINVAL);
	}

	/* Prefer to aesni(4). */
	return (CRYPTODEV_PROBE_ACCEL_SOFTWARE + 10);
}

static int
isal_newsession(device_t dev, crypto_session_t cses,
    const struct crypto_session_params *csp)
{
	struct isal_session *s;

	s = crypto_get_driver_session(cses);

	if (csp->csp_cipher_klen == 16) {
		s->aes_gcm_pre = aes_gcm_pre_128;
		s->aes_gcm_init = aes_gcm_init_128;
		s->aes_gcm_dec_update = aes_gcm_dec_128_update;
		s->aes_gcm_dec_update_nt = aes_gcm_dec_128_update_nt;
		s->aes_gcm_dec_finalize = aes_gcm_dec_128_finalize;
		s->aes_gcm_enc_update = aes_gcm_enc_128_update;
		s->aes_gcm_enc_update_nt = aes_gcm_enc_128_update_nt;
		s->aes_gcm_enc_finalize = aes_gcm_enc_128_finalize;
	} else {
		s->aes_gcm_pre = aes_gcm_pre_256;
		s->aes_gcm_init = aes_gcm_init_256;
		s->aes_gcm_dec_update = aes_gcm_dec_256_update;
		s->aes_gcm_dec_update_nt = aes_gcm_dec_256_update_nt;
		s->aes_gcm_dec_finalize = aes_gcm_dec_256_finalize;
		s->aes_gcm_enc_update = aes_gcm_enc_256_update;
		s->aes_gcm_enc_update_nt = aes_gcm_enc_256_update_nt;
		s->aes_gcm_enc_finalize = aes_gcm_enc_256_finalize;
	}

	if (csp->csp_cipher_key != NULL) {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		s->aes_gcm_pre(csp->csp_cipher_key, &s->key_data);
		fpu_kern_leave(curthread, NULL);
	}

	return (0);
}

static int
isal_process(device_t dev, struct cryptop *crp, int hint)
{
	struct gcm_context_data context_data;
	struct crypto_buffer_cursor cc_in, cc_out;
	struct isal_softc *sc;
	struct isal_session *s;
	void *aad;
	uint8_t *in, *out;
	void (*aes_gcm_update)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	void (*aes_gcm_update_nt)(const struct gcm_key_data *,
	    struct gcm_context_data *, uint8_t *, const uint8_t *, uint64_t);
	uint8_t tag[16];
	size_t inlen, outlen, resid, todo;
	int error;
	bool aad_allocated, fpu_entered;

	aad_allocated = false;
	if ((crp->crp_flags & CRYPTO_F_IV_SEPARATE) == 0) {
		error = EINVAL;
		goto out;
	}

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
			if (aad == NULL) {
				error = ENOMEM;
				goto out;
			}
			aad_allocated = true;
			crypto_copydata(crp, crp->crp_aad_start,
			    crp->crp_aad_length, aad);
		}
	}

	sc = device_get_softc(dev);
	s = crypto_get_driver_session(crp->crp_session);

	if (is_fpu_kern_thread(0)) {
		fpu_entered = false;
	} else {
		fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);
		fpu_entered = true;
	}

	if (crp->crp_cipher_key != NULL)
		s->aes_gcm_pre(crp->crp_cipher_key, &s->key_data);
	s->aes_gcm_init(&s->key_data, &context_data, crp->crp_iv, aad,
	    crp->crp_aad_length);

	if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
		aes_gcm_update = s->aes_gcm_enc_update;
		aes_gcm_update_nt = s->aes_gcm_enc_update_nt;
	} else {
		aes_gcm_update = s->aes_gcm_dec_update;
		aes_gcm_update_nt = s->aes_gcm_dec_update_nt;
	}

	crypto_cursor_init(&cc_in, &crp->crp_buf);
	crypto_cursor_advance(&cc_in, crp->crp_payload_start);
	resid = crp->crp_payload_length;
	if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
		crypto_cursor_init(&cc_out, &crp->crp_obuf);
		crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);

		in = crypto_cursor_segment(&cc_in, &inlen);
		out = crypto_cursor_segment(&cc_out, &outlen);

		/*
		 * Use aes_gcm_update_nt so long as both buffers are
		 * 16 bytes aligned.
		 */
		while (resid > 0 && inlen >= 16 && outlen >= 16 &&
		    (uintptr_t)in % 16 == 0 && (uintptr_t)out % 16 == 0) {
			todo = MIN(MIN(inlen, outlen), resid);
			if (todo > 16)
				todo = rounddown2(todo, 16);

			aes_gcm_update_nt(&s->key_data, &context_data, out, in,
			    todo);

			crypto_cursor_advance(&cc_in, todo);
			inlen -= todo;
			if (inlen == 0)
				in = crypto_cursor_segment(&cc_in, &inlen);
			else
				in += todo;

			crypto_cursor_advance(&cc_out, todo);
			outlen -= todo;
			if (outlen == 0)
				out = crypto_cursor_segment(&cc_out, &outlen);
			else
				out += todo;

			resid -= todo;
			counter_u64_add(sc->sc_gcm_update_nt_bytes, todo);
			counter_u64_add(sc->sc_gcm_update_nt_calls, 1);
		}

		/*
		 * Fallback to aes_gcm_update once we hit any
		 * unaligned data.
		 */
		while (resid > 0) {
			todo = MIN(MIN(inlen, outlen), resid);
			
			aes_gcm_update(&s->key_data, &context_data, out, in,
			    todo);

			crypto_cursor_advance(&cc_in, todo);
			inlen -= todo;
			if (inlen == 0)
				in = crypto_cursor_segment(&cc_in, &inlen);
			else
				in += todo;

			crypto_cursor_advance(&cc_out, todo);
			outlen -= todo;
			if (outlen == 0)
				out = crypto_cursor_segment(&cc_out, &outlen);
			else
				out += todo;

			resid -= todo;
			counter_u64_add(sc->sc_gcm_update_bytes, todo);
			counter_u64_add(sc->sc_gcm_update_calls, 1);
		}
	} else {
		while (resid > 0) {
			in = crypto_cursor_segment(&cc_in, &todo);
			if (todo > resid)
				todo = resid;
			aes_gcm_update(&s->key_data, &context_data, in, in,
			    todo);
			crypto_cursor_advance(&cc_in, todo);
			resid -= todo;
			counter_u64_add(sc->sc_gcm_update_bytes, todo);
			counter_u64_add(sc->sc_gcm_update_calls, 1);
		}
	}

	error = 0;

	if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
		s->aes_gcm_enc_finalize(&s->key_data, &context_data, tag,
		    sizeof(tag));
		crypto_copyback(crp, crp->crp_digest_start, sizeof(tag), tag);
		counter_u64_add(sc->sc_gcm_encrypt, 1);
	} else {
		uint8_t tag2[16];

		s->aes_gcm_dec_finalize(&s->key_data, &context_data, tag,
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

out:
	if (aad_allocated)
		free(aad, M_ISAL);
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
	DEVMETHOD(cryptodev_process,	isal_process),

	DEVMETHOD_END
};

static driver_t isal_driver = {
	"isal",
	isal_methods,
	sizeof(struct isal_softc)
};

#if __FreeBSD_version >= 1400058
DRIVER_MODULE(isal, nexus, isal_driver, NULL, NULL);
#else
static devclass_t isal_devclass;

DRIVER_MODULE(isal, nexus, isal_driver, isal_devclass, NULL, NULL);
#endif
MODULE_VERSION(isal, 1);
MODULE_DEPEND(isal, crypto, 1, 1, 1);
