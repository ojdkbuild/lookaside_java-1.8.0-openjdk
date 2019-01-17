/*
 * Copyright (c) 2007, 2012, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/* *********************************************************************
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Dr Vipul Gupta <vipul.gupta@sun.com>, Sun Microsystems Laboratories
 *
 * Last Modified Date from the Original Code: March 2012
 *********************************************************************** */

#include <sys/types.h>

#ifndef _WIN32
#if !defined(__linux__) && !defined(_ALLBSD_SOURCE)
#include <sys/systm.h>
#endif /* __linux__ || _ALLBSD_SOURCE */
#include <sys/param.h>
#endif /* _WIN32 */

#ifdef _KERNEL
#include <sys/kmem.h>
#else
#include <string.h>
#endif
#include "ec.h"
#include "ecl-curve.h"
#include "ecc_impl.h"
#include "secoidt.h"

#define CERTICOM_OID            0x2b, 0x81, 0x04
#define SECG_OID                CERTICOM_OID, 0x00

#define ANSI_X962_OID           0x2a, 0x86, 0x48, 0xce, 0x3d
#define ANSI_X962_CURVE_OID     ANSI_X962_OID, 0x03
#define ANSI_X962_GF2m_OID      ANSI_X962_CURVE_OID, 0x00
#define ANSI_X962_GFp_OID       ANSI_X962_CURVE_OID, 0x01

#define CONST_OID static const unsigned char

/* ANSI X9.62 prime curve OIDs */
/* NOTE: prime192v1 is the same as secp192r1, prime256v1 is the
 * same as secp256r1
 */
CONST_OID ansiX962prime256v1[] = { ANSI_X962_GFp_OID, 0x07 };

/* SECG prime curve OIDs */
CONST_OID secgECsecp384r1[] = { SECG_OID, 0x22 };
CONST_OID secgECsecp521r1[] = { SECG_OID, 0x23 };

#define OI(x) { siDEROID, (unsigned char *)x, sizeof x }
#ifndef SECOID_NO_STRINGS
#define OD(oid,tag,desc,mech,ext) { OI(oid), tag, desc, mech, ext }
#else
#define OD(oid,tag,desc,mech,ext) { OI(oid), tag, 0, mech, ext }
#endif

#define CKM_INVALID_MECHANISM 0xffffffffUL

/* XXX this is incorrect */
#define INVALID_CERT_EXTENSION 1

#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042
#define CKM_ECDH1_DERIVE               0x00001050

static SECOidData ANSI_prime_oids[] = {
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },

    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    OD( ansiX962prime256v1, ECCurve_NIST_P256,
        "ANSI X9.62 elliptic curve prime256v1 (aka secp256r1, NIST P-256)",
        CKM_INVALID_MECHANISM,
        INVALID_CERT_EXTENSION )
};

static SECOidData SECG_oids[] = {
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },

    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    OD( secgECsecp384r1, ECCurve_NIST_P384,
        "SECG elliptic curve secp384r1 (aka NIST P-384)",
        CKM_INVALID_MECHANISM,
        INVALID_CERT_EXTENSION ),
    OD( secgECsecp521r1, ECCurve_NIST_P521,
        "SECG elliptic curve secp521r1 (aka NIST P-521)",
        CKM_INVALID_MECHANISM,
        INVALID_CERT_EXTENSION ),
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION }
};

static SECOidData ANSI_oids[] = {
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },

    /* ANSI X9.62 named elliptic curves (characteristic two field) */
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION },
    { { siDEROID, NULL, 0 }, ECCurve_noName,
        "Unknown OID", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION }
};

SECOidData *
SECOID_FindOID(const SECItem *oid)
{
    SECOidData *po;
    SECOidData *ret = NULL;

    if (oid->len == 8) {
        if (oid->data[6] == 0x00) {
                /* XXX bounds check */
                po = &ANSI_oids[oid->data[7]];
                if (memcmp(oid->data, po->oid.data, 8) == 0)
                        ret = po;
        }
        if (oid->data[6] == 0x01) {
                /* XXX bounds check */
                po = &ANSI_prime_oids[oid->data[7]];
                if (memcmp(oid->data, po->oid.data, 8) == 0)
                        ret = po;
        }
    } else if (oid->len == 5) {
        /* XXX bounds check */
        po = &SECG_oids[oid->data[4]];
        if (memcmp(oid->data, po->oid.data, 5) == 0)
                ret = po;
    }
    return(ret);
}

ECCurveName
SECOID_FindOIDTag(const SECItem *oid)
{
    SECOidData *oiddata;

    oiddata = SECOID_FindOID (oid);
    if (oiddata == NULL)
        return ECCurve_noName;

    return oiddata->offset;
}
