#
# Copyright (c) 2016-2020 Netflix, Inc
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer,
#    without modification.
# 2. Redistributions in binary form must reproduce at minimum a disclaimer
#    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
#    redistribution must be conditioned upon including a substantially
#    similar Disclaimer requirement for further binary redistribution.
#
# NO WARRANTY
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGES.
#

ISASRC?=${.CURDIR}/isa-l_crypto
INCS=	-I${ISASRC}/include -I${ISASRC}/aes
INCS+=	-I${ISASRC}/mh_sha1 -I${ISASRC}/mh_sha256
INCS+=	-I${.CURDIR}/include
CFLAGS+=${INCS}
LOCALBASE?=/usr/local
YASM?=	${LOCALBASE}/bin/yasm

.PATH: ${ISASRC}/aes ${ISASRC}/mh_sha1  ${ISASRC}/mh_sha256

.SUFFIXES: .asm

.asm.o:
	${YASM} -g dwarf2 -f elf64 ${INCS} -o ${.TARGET} ${.IMPSRC}

KMOD=	isal
SRCS=	cbc_dec_128_x4_sse.asm \
	cbc_dec_128_x8_avx.asm \
	cbc_dec_192_x4_sse.asm \
	cbc_dec_192_x8_avx.asm \
	cbc_dec_256_x4_sse.asm \
	cbc_dec_256_x8_avx.asm \
	cbc_enc_128_x4_sb.asm \
	cbc_enc_128_x8_sb.asm \
	cbc_enc_192_x4_sb.asm \
	cbc_enc_192_x8_sb.asm \
	cbc_enc_256_x4_sb.asm \
	cbc_enc_256_x8_sb.asm \
	cbc_multibinary.asm \
	cbc_pre.c \
	gcm128_avx_gen2.asm \
	gcm128_avx_gen4.asm \
	gcm128_sse.asm \
	gcm256_avx_gen2.asm \
	gcm256_avx_gen4.asm \
	gcm256_sse.asm \
	gcm_multibinary.asm \
	gcm128_avx_gen2_nt.asm \
	gcm128_avx_gen4_nt.asm \
	gcm128_sse_nt.asm \
	gcm256_avx_gen2_nt.asm \
	gcm256_avx_gen4_nt.asm \
	gcm256_sse_nt.asm \
	gcm_multibinary_nt.asm \
	gcm_pre.c \
	keyexp_128.asm \
	keyexp_192.asm \
	keyexp_256.asm \
	keyexp_multibinary.asm \
	mh_sha1_block_avx.asm \
	mh_sha1_block_avx2.asm \
	mh_sha1_block_sse.asm \
	mh_sha1_multibinary.asm \
	mh_sha1.c \
	mh_sha1_block_base.c \
	mh_sha1_finalize_base.c \
	mh_sha1_update_base.c \
	sha1_for_mh_sha1.c \
	mh_sha256_block_avx.asm \
	mh_sha256_block_avx2.asm \
	mh_sha256_block_sse.asm \
	mh_sha256_multibinary.asm \
	mh_sha256.c \
	mh_sha256_block_base.c \
	mh_sha256_finalize_base.c \
	mh_sha256_update_base.c \
	sha256_for_mh_sha256.c \
	isal_ocf.c \
	bus_if.h \
	cryptodev_if.h \
	device_if.h

CWARNFLAGS.mh_sha1_block_base.c+=-Wno-missing-prototypes ${NO_WCAST_QUAL}
CWARNFLAGS.mh_sha256_block_base.c+=-Wno-missing-prototypes ${NO_WCAST_QUAL}
CWARNFLAGS.sha1_for_mh_sha1.c+=${NO_WCAST_QUAL}
CWARNFLAGS.sha256_for_mh_sha256.c+=${NO_WCAST_QUAL}

.include <bsd.kmod.mk>
