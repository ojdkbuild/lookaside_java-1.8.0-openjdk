/*
 * reserved comment block
 * DO NOT REMOVE OR ALTER!
 */
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.sun.org.apache.xml.internal.security.algorithms.implementations;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public final class ECDSAUtils {

    private ECDSAUtils() {
        // complete
    }

    /**
     * Converts an ASN.1 ECDSA value to a XML Signature ECDSA Value.
     * <p></p>
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r, s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param asn1Bytes
     * @return the decode bytes
     * @throws IOException
     * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
     * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
     */
    public static byte[] convertASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {

        if (asn1Bytes.length < 8 || asn1Bytes[0] != 48) {
            throw new IOException("Invalid ASN.1 format of ECDSA signature");
        }
        int offset;
        if (asn1Bytes[1] > 0) {
            offset = 2;
        } else if (asn1Bytes[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new IOException("Invalid ASN.1 format of ECDSA signature");
        }

        byte rLength = asn1Bytes[offset + 1];
        int i;

        for (i = rLength; i > 0 && asn1Bytes[offset + 2 + rLength - i] == 0; i--); //NOPMD

        byte sLength = asn1Bytes[offset + 2 + rLength + 1];
        int j;

        for (j = sLength; j > 0 && asn1Bytes[offset + 2 + rLength + 2 + sLength - j] == 0; j--); //NOPMD

        int rawLen = Math.max(i, j);

        if ((asn1Bytes[offset - 1] & 0xff) != asn1Bytes.length - offset
                || (asn1Bytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || asn1Bytes[offset] != 2
                || asn1Bytes[offset + 2 + rLength] != 2) {
            throw new IOException("Invalid ASN.1 format of ECDSA signature");
        }
        byte xmldsigBytes[] = new byte[2 * rawLen];

        System.arraycopy(asn1Bytes, offset + 2 + rLength - i, xmldsigBytes, rawLen - i, i);
        System.arraycopy(asn1Bytes, offset + 2 + rLength + 2 + sLength - j, xmldsigBytes,
                2 * rawLen - j, j);

        return xmldsigBytes;
    }

    /**
     * Converts a XML Signature ECDSA Value to an ASN.1 DSA value.
     * <p></p>
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r, s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param xmldsigBytes
     * @return the encoded ASN.1 bytes
     * @throws IOException
     * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
     * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
     */
    public static byte[] convertXMLDSIGtoASN1(byte xmldsigBytes[]) throws IOException {

        int rawLen = xmldsigBytes.length / 2;

        int i;

        for (i = rawLen; i > 0 && xmldsigBytes[rawLen - i] == 0; i--); //NOPMD

        int j = i;

        if (xmldsigBytes[rawLen - i] < 0) {
            j += 1;
        }

        int k;

        for (k = rawLen; k > 0 && xmldsigBytes[2 * rawLen - k] == 0; k--); //NOPMD

        int l = k;

        if (xmldsigBytes[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;
        if (len > 255) {
            throw new IOException("Invalid XMLDSIG format of ECDSA signature");
        }
        int offset;
        byte asn1Bytes[];
        if (len < 128) {
            asn1Bytes = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            asn1Bytes = new byte[3 + 2 + j + 2 + l];
            asn1Bytes[1] = (byte) 0x81;
            offset = 2;
        }
        asn1Bytes[0] = 48;
        asn1Bytes[offset++] = (byte) len;
        asn1Bytes[offset++] = 2;
        asn1Bytes[offset++] = (byte) j;

        System.arraycopy(xmldsigBytes, rawLen - i, asn1Bytes, offset + j - i, i);

        offset += j;

        asn1Bytes[offset++] = 2;
        asn1Bytes[offset++] = (byte) l;

        System.arraycopy(xmldsigBytes, 2 * rawLen - k, asn1Bytes, offset + l - k, k);

        return asn1Bytes;
    }

    private static final List<ECCurveDefinition> ecCurveDefinitions = new ArrayList<>();

    static {
        ecCurveDefinitions.add(
                new ECCurveDefinition(
                        "secp256k1",
                        "1.3.132.0.10",
                        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000007",
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                        1)
        );

        ecCurveDefinitions.add(
                new ECCurveDefinition(
                        "secp256r1 [NIST P-256, X9.62 prime256v1]",
                        "1.2.840.10045.3.1.7",
                        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                        1)
        );

        ecCurveDefinitions.add(
                new ECCurveDefinition(
                        "secp384r1 [NIST P-384]",
                        "1.3.132.0.34",
                        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
                        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                        1)
        );

        ecCurveDefinitions.add(
                new ECCurveDefinition(
                        "secp521r1 [NIST P-521]",
                        "1.3.132.0.35",
                        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
                        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
                        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
                        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
                        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
                        1)
        );
    }

    public static String getOIDFromPublicKey(ECPublicKey ecPublicKey) {
        ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
        BigInteger order = ecParameterSpec.getOrder();
        BigInteger affineX = ecParameterSpec.getGenerator().getAffineX();
        BigInteger affineY = ecParameterSpec.getGenerator().getAffineY();
        BigInteger a = ecParameterSpec.getCurve().getA();
        BigInteger b = ecParameterSpec.getCurve().getB();
        int h = ecParameterSpec.getCofactor();
        ECField ecField = ecParameterSpec.getCurve().getField();
        BigInteger field;
        if (ecField instanceof ECFieldFp) {
            ECFieldFp ecFieldFp = (ECFieldFp) ecField;
            field = ecFieldFp.getP();
        } else {
            ECFieldF2m ecFieldF2m = (ECFieldF2m) ecField;
            field = ecFieldF2m.getReductionPolynomial();
        }

        Iterator<ECCurveDefinition> ecCurveDefinitionIterator = ecCurveDefinitions.iterator();
        while (ecCurveDefinitionIterator.hasNext()) {
            ECCurveDefinition ecCurveDefinition = ecCurveDefinitionIterator.next();
            String oid = ecCurveDefinition.equals(field, a, b, affineX, affineY, order, h);
            if (oid != null) {
                return oid;
            }
        }
        return null;
    }

    public static ECCurveDefinition getECCurveDefinition(String oid) {
        Iterator<ECCurveDefinition> ecCurveDefinitionIterator = ecCurveDefinitions.iterator();
        while (ecCurveDefinitionIterator.hasNext()) {
            ECCurveDefinition ecCurveDefinition = ecCurveDefinitionIterator.next();
            if (ecCurveDefinition.getOid().equals(oid)) {
                return ecCurveDefinition;
            }
        }
        return null;
    }

    public static class ECCurveDefinition {

        private final String name;
        private final String oid;
        private final String field;
        private final String a;
        private final String b;
        private final String x;
        private final String y;
        private final String n;
        private final int h;

        public ECCurveDefinition(String name, String oid, String field, String a, String b, String x, String y, String n, int h) {
            this.name = name;
            this.oid = oid;
            this.field = field;
            this.a = a;
            this.b = b;
            this.x = x;
            this.y = y;
            this.n = n;
            this.h = h;
        }

        /**
         * returns the ec oid if parameter are equal to this definition
         */
        public String equals(BigInteger field, BigInteger a, BigInteger b, BigInteger x, BigInteger y, BigInteger n, int h) {
            if (this.field.equals(field.toString(16))
                    && this.a.equals(a.toString(16))
                    && this.b.equals(b.toString(16))
                    && this.x.equals(x.toString(16))
                    && this.y.equals(y.toString(16))
                    && this.n.equals(n.toString(16))
                    && this.h == h) {
                return this.oid;
            }
            return null;
        }

        public String getName() {
            return name;
        }

        public String getOid() {
            return oid;
        }

        public String getField() {
            return field;
        }

        public String getA() {
            return a;
        }

        public String getB() {
            return b;
        }

        public String getX() {
            return x;
        }

        public String getY() {
            return y;
        }

        public String getN() {
            return n;
        }

        public int getH() {
            return h;
        }
    }

    public static byte[] encodePoint(ECPoint ecPoint, EllipticCurve ellipticCurve) {
        int size = (ellipticCurve.getField().getFieldSize() + 7) / 8;
        byte affineXBytes[] = stripLeadingZeros(ecPoint.getAffineX().toByteArray());
        byte affineYBytes[] = stripLeadingZeros(ecPoint.getAffineY().toByteArray());
        byte encodedBytes[] = new byte[size * 2 + 1];
        encodedBytes[0] = 0x04; //uncompressed
        System.arraycopy(affineXBytes, 0, encodedBytes, size - affineXBytes.length + 1, affineXBytes.length);
        System.arraycopy(affineYBytes, 0, encodedBytes, encodedBytes.length - affineYBytes.length, affineYBytes.length);
        return encodedBytes;
    }

    public static ECPoint decodePoint(byte[] encodedBytes, EllipticCurve elliptiCcurve) {
        if (encodedBytes[0] != 0x04) {
            throw new IllegalArgumentException("Only uncompressed format is supported");
        }

        int size = (elliptiCcurve.getField().getFieldSize() + 7) / 8;
        byte affineXBytes[] = new byte[size];
        byte affineYBytes[] = new byte[size];
        System.arraycopy(encodedBytes, 1, affineXBytes, 0, size);
        System.arraycopy(encodedBytes, size + 1, affineYBytes, 0, size);
        return new ECPoint(new BigInteger(1, affineXBytes), new BigInteger(1, affineYBytes));
    }

    public static byte[] stripLeadingZeros(byte[] bytes) {
        int i;
        for (i = 0; i < bytes.length - 1; i++) {
            if (bytes[i] != 0) {
                break;
            }
        }

        if (i == 0) {
            return bytes;
        } else {
            byte stripped[] = new byte[bytes.length - i];
            System.arraycopy(bytes, i, stripped, 0, stripped.length);
            return stripped;
        }
    }
}
