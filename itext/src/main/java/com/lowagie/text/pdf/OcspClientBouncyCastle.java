/*
 * $Id$
 *
 * Copyright 2009 Paulo Soares
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999-2005 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2009 by Paulo Soares. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * http://www.lowagie.com/iText/
 */

package com.lowagie.text.pdf;

import com.lowagie.text.ExceptionConverter;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * OcspClient implementation using BouncyCastle.
 *
 * @author psoares
 * @since 2.1.6
 */
public class OcspClientBouncyCastle implements OcspClient {
    /**
     * root certificate
     */
    private final X509Certificate rootCert;
    /**
     * check certificate
     */
    private final X509Certificate checkCert;
    /**
     * OCSP URL
     */
    private final String url;

    /**
     * Creates an instance of an OcspClient that will be using BouncyCastle.
     *
     * @param checkCert the check certificate
     * @param rootCert  the root certificate
     * @param url       the OCSP URL
     */
    public OcspClientBouncyCastle(X509Certificate checkCert, X509Certificate rootCert, String url) {
        this.checkCert = checkCert;
        this.rootCert = rootCert;
        this.url = url;
    }

    /**
     * Generates an OCSP request using BouncyCastle.
     *
     * @param issuerCert   certificate of the issuer
     * @param serialNumber serial number
     * @return an OCSP request
     * @throws IOException if generation fails
     */
    public static byte[] generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws IOException {
        // Add BC provider if not already present
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Step 1: Build the CertificateID (Issuer and Serial Number)
        ASN1EncodableVector certIDVector = new ASN1EncodableVector();

        // CertificateIssuer (issuer certificate subject hash)
        certIDVector.add(new DEROctetString(issuerCert.getIssuerX500Principal().getEncoded()));

        // CertificateSerialNumber (serial number of the certificate)
        certIDVector.add(new ASN1Integer(serialNumber));

        // Hash algorithm (SHA1)
        certIDVector.add(new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA1 hash OID

        // Create CertificateID using ASN.1 structures
        DERSequence certID = new DERSequence(certIDVector);

        // Step 2: Create the Request (CertificateID)
        ASN1EncodableVector requestVector = new ASN1EncodableVector();
        requestVector.add(certID);

        // Step 3: Extensions (nonces or other optional data)
        List<ASN1Encodable> oids = new ArrayList<>();

        byte[] nonce = BigInteger.valueOf(System.currentTimeMillis()).toByteArray();
        DEROctetString nonceExtension = new DEROctetString(nonce);

        // Using Extension and Extensions from BouncyCastle 1.8
        Extension nonceExt = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonceExtension);
        oids.add(nonceExt);

        // Step 4: Create Extensions (using ASN1EncodableVector and DERSequence)
        ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
        for (ASN1Encodable oid : oids) {
            extensionsVector.add(oid);
        }

        // Create final Extensions sequence
        ASN1Sequence extensions = new DERSequence(extensionsVector);

        // Step 5: Create TBSRequest (To Be Signed)
        ASN1EncodableVector tbsRequestVector = new ASN1EncodableVector();
        tbsRequestVector.add(new ASN1Integer(1)); // Version (set to 1)
        tbsRequestVector.add(new DERSequence(requestVector)); // Request
        tbsRequestVector.add(extensions); // Extensions

        // Create TBSRequest (To Be Signed) using DER encoding
        ASN1Sequence tbsRequestSequence = new DERSequence(tbsRequestVector);

        // Step 6: Create OCSPRequest (entire request)
        // Use the DER-encoded TBSRequest for the OCSP request
        ASN1EncodableVector ocspRequestVector = new ASN1EncodableVector();
        ocspRequestVector.add(tbsRequestSequence);

        // Create final OCSPRequest
        ASN1Sequence ocspRequestSequence = new DERSequence(ocspRequestVector);

        // Step 7: Return the DER-encoded OCSPRequest
        return ocspRequestSequence.getEncoded(); // Returns byte array (DER encoding)
    }

    /**
     * @return a byte array
     * @see com.lowagie.text.pdf.OcspClient#getEncoded()
     */
    public byte[] getEncoded() {
        try {
            // Gọi hàm generateOCSPRequest để tạo yêu cầu OCSP
            byte[] ocspRequestBytes = generateOCSPRequest(rootCert, checkCert.getSerialNumber());

            // Gửi OCSP request tới server
            URL urlt = new URI(url).toURL();
            HttpURLConnection con = (HttpURLConnection) urlt.openConnection();
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);

            try (OutputStream out = con.getOutputStream();
                 DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out))) {
                dataOut.write(ocspRequestBytes);
                dataOut.flush();
            }

            if (con.getResponseCode() / 100 != 2) {
                throw new IOException("Invalid HTTP response");
            }

            // Đọc phản hồi OCSP và phân tích bằng OCSPResponse (BouncyCastle 1.8+)
            try (InputStream in = con.getInputStream();
                 ASN1InputStream asn1InputStream = new ASN1InputStream(in)) {

                ASN1Primitive asn1Resp = asn1InputStream.readObject();
                OCSPResponse ocspResponse = OCSPResponse.getInstance(asn1Resp);

                // Kiểm tra trạng thái phản hồi
                ASN1Enumerated responseStatus = ASN1Enumerated.getInstance(ocspResponse.getResponseStatus());
                if (responseStatus.getValue().intValue() != OCSPResponseStatus.SUCCESSFUL) {
                    throw new IOException("OCSP response status not successful: " + responseStatus.getValue().intValue());
                }

                // Lấy responseBytes
                ResponseBytes responseBytes = ocspResponse.getResponseBytes();
                if (responseBytes == null || !responseBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                    throw new IOException("Invalid or missing OCSP response bytes");
                }

                // Parse lại basicOCSPResponse
                ASN1InputStream basicIn = new ASN1InputStream(responseBytes.getResponse().getOctets());
                ASN1Primitive basicOcspAsn1 = basicIn.readObject();
                ASN1Sequence basicOcspSeq = ASN1Sequence.getInstance(basicOcspAsn1);
                basicIn.close();

                // Lấy SingleResponse từ cấu trúc ASN1
                ASN1Sequence tbsResponseData = (ASN1Sequence) basicOcspSeq.getObjectAt(0);
                ASN1Sequence responsesSeq = (ASN1Sequence) tbsResponseData.getObjectAt(6); // index 6: responses

                ASN1Sequence singleResp = (ASN1Sequence) responsesSeq.getObjectAt(0);
                ASN1TaggedObject certStatusObj = (ASN1TaggedObject) singleResp.getObjectAt(1); // certStatus là tagged

                int tagNo = certStatusObj.getTagNo();
                return switch (tagNo) {
                    case 0 -> responseBytes.getResponse().getOctets();
                    case 1 -> throw new IOException("OCSP status: revoked");
                    default -> throw new IOException("OCSP status: unknown");
                };
            }

        } catch (Exception ex) {
            throw new ExceptionConverter(ex);
        }
    }
}
