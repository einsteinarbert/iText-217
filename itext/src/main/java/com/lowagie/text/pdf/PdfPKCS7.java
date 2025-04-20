/*
 * Copyright 2004 by Paulo Soares.
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
 * the Initial Developer are Copyright (C) 1999, 2000, 2001, 2002 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000, 2001, 2002 by Paulo Soares. All Rights Reserved.
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

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRL;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.lowagie.text.ExceptionConverter;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;

import static org.bouncycastle.its.ITSAlgorithmUtils.getHashAlgorithm;

/**
 * This class does all the processing related to signing and verifying a PKCS#7
 * signature.
 * <p>
 * It's based in code found at org.bouncycastle.
 */
public class PdfPKCS7 {

    private byte sigAttr[];
    private byte digestAttr[];
    private int version, signerversion;
    private Set digestalgos;
    private Collection certs, crls, signCerts;
    private X509Certificate signCert;
    private byte[] digest;
    private MessageDigest messageDigest;
    private String digestAlgorithm, digestEncryptionAlgorithm;
    private Signature sig;
    private transient PrivateKey privKey;
    private byte RSAdata[];
    private boolean verified;
    private boolean verifyResult;
    private byte externalDigest[];
    private byte externalRSAdata[];
    private String provider;

    private static final String ID_PKCS7_DATA = "1.2.840.113549.1.7.1";
    private static final String ID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";
    private static final String ID_RSA = "1.2.840.113549.1.1.1";
    private static final String ID_DSA = "1.2.840.10040.4.1";
    private static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    private static final String ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";
    private static final String ID_ADBE_REVOCATION = "1.2.840.113583.1.1.8";
    /**
     * Holds value of property reason.
     */
    private String reason;

    /**
     * Holds value of property location.
     */
    private String location;

    /**
     * Holds value of property signDate.
     */
    private Calendar signDate;

    /**
     * Holds value of property signName.
     */
    private String signName;

    private TimeStampToken timeStampToken;

    private static final HashMap digestNames = new HashMap();
    private static final HashMap algorithmNames = new HashMap();
    private static final HashMap allowedDigests = new HashMap();

    static {
        digestNames.put("1.2.840.113549.2.5", "MD5");
        digestNames.put("1.2.840.113549.2.2", "MD2");
        digestNames.put("1.3.14.3.2.26", "SHA1");
        digestNames.put("2.16.840.1.101.3.4.2.4", "SHA224");
        digestNames.put("2.16.840.1.101.3.4.2.1", "SHA256");
        digestNames.put("2.16.840.1.101.3.4.2.2", "SHA384");
        digestNames.put("2.16.840.1.101.3.4.2.3", "SHA512");
        digestNames.put("1.3.36.3.2.2", "RIPEMD128");
        digestNames.put("1.3.36.3.2.1", "RIPEMD160");
        digestNames.put("1.3.36.3.2.3", "RIPEMD256");
        digestNames.put("1.2.840.113549.1.1.4", "MD5");
        digestNames.put("1.2.840.113549.1.1.2", "MD2");
        digestNames.put("1.2.840.113549.1.1.5", "SHA1");
        digestNames.put("1.2.840.113549.1.1.14", "SHA224");
        digestNames.put("1.2.840.113549.1.1.11", "SHA256");
        digestNames.put("1.2.840.113549.1.1.12", "SHA384");
        digestNames.put("1.2.840.113549.1.1.13", "SHA512");
        digestNames.put("1.2.840.113549.2.5", "MD5");
        digestNames.put("1.2.840.113549.2.2", "MD2");
        digestNames.put("1.2.840.10040.4.3", "SHA1");
        digestNames.put("2.16.840.1.101.3.4.3.1", "SHA224");
        digestNames.put("2.16.840.1.101.3.4.3.2", "SHA256");
        digestNames.put("2.16.840.1.101.3.4.3.3", "SHA384");
        digestNames.put("2.16.840.1.101.3.4.3.4", "SHA512");
        digestNames.put("1.3.36.3.3.1.3", "RIPEMD128");
        digestNames.put("1.3.36.3.3.1.2", "RIPEMD160");
        digestNames.put("1.3.36.3.3.1.4", "RIPEMD256");

        algorithmNames.put("1.2.840.113549.1.1.1", "RSA");
        algorithmNames.put("1.2.840.10040.4.1", "DSA");
        algorithmNames.put("1.2.840.113549.1.1.2", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.4", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.5", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.14", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.11", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.12", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.13", "RSA");
        algorithmNames.put("1.2.840.10040.4.3", "DSA");
        algorithmNames.put("2.16.840.1.101.3.4.3.1", "DSA");
        algorithmNames.put("2.16.840.1.101.3.4.3.2", "DSA");
        algorithmNames.put("1.3.36.3.3.1.3", "RSA");
        algorithmNames.put("1.3.36.3.3.1.2", "RSA");
        algorithmNames.put("1.3.36.3.3.1.4", "RSA");

        allowedDigests.put("MD5", "1.2.840.113549.2.5");
        allowedDigests.put("MD2", "1.2.840.113549.2.2");
        allowedDigests.put("SHA1", "1.3.14.3.2.26");
        allowedDigests.put("SHA224", "2.16.840.1.101.3.4.2.4");
        allowedDigests.put("SHA256", "2.16.840.1.101.3.4.2.1");
        allowedDigests.put("SHA384", "2.16.840.1.101.3.4.2.2");
        allowedDigests.put("SHA512", "2.16.840.1.101.3.4.2.3");
        allowedDigests.put("MD-5", "1.2.840.113549.2.5");
        allowedDigests.put("MD-2", "1.2.840.113549.2.2");
        allowedDigests.put("SHA-1", "1.3.14.3.2.26");
        allowedDigests.put("SHA-224", "2.16.840.1.101.3.4.2.4");
        allowedDigests.put("SHA-256", "2.16.840.1.101.3.4.2.1");
        allowedDigests.put("SHA-384", "2.16.840.1.101.3.4.2.2");
        allowedDigests.put("SHA-512", "2.16.840.1.101.3.4.2.3");
        allowedDigests.put("RIPEMD128", "1.3.36.3.2.2");
        allowedDigests.put("RIPEMD-128", "1.3.36.3.2.2");
        allowedDigests.put("RIPEMD160", "1.3.36.3.2.1");
        allowedDigests.put("RIPEMD-160", "1.3.36.3.2.1");
        allowedDigests.put("RIPEMD256", "1.3.36.3.2.3");
        allowedDigests.put("RIPEMD-256", "1.3.36.3.2.3");
    }

    /**
     * Gets the digest name for a certain id
     *
     * @param oid an id (for instance "1.2.840.113549.2.5")
     * @return a digest name (for instance "MD5")
     * @since 2.1.6
     */
    public static String getDigest(String oid) {
        String ret = (String) digestNames.get(oid);
        if (ret == null)
            return oid;
        else
            return ret;
    }

    /**
     * Gets the algorithm name for a certain id.
     *
     * @param oid an id (for instance "1.2.840.113549.1.1.1")
     * @return an algorithm name (for instance "RSA")
     * @since 2.1.6
     */
    public static String getAlgorithm(String oid) {
        String ret = (String) algorithmNames.get(oid);
        if (ret == null)
            return oid;
        else
            return ret;
    }

    /**
     * Gets the timestamp token if there is one.
     *
     * @return the timestamp token or null
     * @since 2.1.6
     */
    public TimeStampToken getTimeStampToken() {
        return timeStampToken;
    }

    /**
     * Gets the timestamp date
     *
     * @return a date
     * @since 2.1.6
     */
    public Calendar getTimeStampDate() {
        if (timeStampToken == null)
            return null;
        Calendar cal = new GregorianCalendar();
        Date date = timeStampToken.getTimeStampInfo().getGenTime();
        cal.setTime(date);
        return cal;
    }

    /**
     * Verifies a signature using the sub-filter adbe.x509.rsa_sha1.
     *
     * @param contentsKey the /Contents key
     * @param certsKey    the /Cert key
     * @param provider    the provider or <code>null</code> for the default provider
     */
    public PdfPKCS7(byte[] contentsKey, byte[] certsKey, String provider) {
        try {
            Collection<X509Certificate> certs = new ArrayList<>();
            this.provider = provider;
            X509CertificateHolder certHolder = new X509CertificateHolder(certsKey);
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");
            ByteArrayInputStream in = new ByteArrayInputStream(certsKey);

            while (in.available() > 0) {
                X509CertificateHolder holder = new X509CertificateHolder(Certificate.getInstance(in));
                certs.add(converter.getCertificate(holder));
            }

            signCerts = certs;
            signCert = certs.iterator().next();
            crls = new ArrayList<X509Certificate>();
            ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(contentsKey));
            digest = ((DEROctetString) inputStream.readObject()).getOctets();
            if (provider == null)
                sig = Signature.getInstance("SHA1withRSA");
            else
                sig = Signature.getInstance("SHA1withRSA", provider);
            sig.initVerify(signCert.getPublicKey());
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    private BasicOCSPResp basicResp;

    /**
     * Gets the OCSP basic response if there is one.
     *
     * @return the OCSP basic response or null
     * @since 2.1.6
     */
    public BasicOCSPResp getOcsp() {
        return basicResp;
    }

    private void findOcsp(ASN1Sequence seq) throws IOException {
        basicResp = null;
        boolean ret = false;
        while (true) {
            if ((seq.getObjectAt(0) instanceof ASN1ObjectIdentifier)
                    && ((ASN1ObjectIdentifier) seq.getObjectAt(0)).getId().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic.getId())) {
                break;
            }
            ret = true;
            for (int k = 0; k < seq.size(); ++k) {
                ASN1Encodable obj = seq.getObjectAt(k);

                if (obj instanceof ASN1Sequence) {
                    seq = (ASN1Sequence) obj;
                    ret = false;
                    break;
                }

                if (obj instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tag = (ASN1TaggedObject) obj;

                    try {
                        ASN1Sequence innerSeq = ASN1Sequence.getInstance(tag, true); // explicit tag
                        seq = innerSeq;
                        ret = false;
                        break;
                    } catch (IllegalArgumentException e) {
                        // Not a sequence inside tag, just return
                        return;
                    }
                }
            }
            if (ret)
                return;
        }
        DEROctetString os = (DEROctetString) seq.getObjectAt(1);
        ASN1InputStream inp = new ASN1InputStream(os.getOctets());
        BasicOCSPResponse resp = BasicOCSPResponse.getInstance(inp.readObject());
        basicResp = new BasicOCSPResp(resp);
    }

    public Collection<X509CRL> loadCrls(byte[] contentsKey) throws Exception {
        Collection<X509CRL> crls = new ArrayList<>();
        ByteArrayInputStream bais = new ByteArrayInputStream(contentsKey);
        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");

        while (bais.available() > 0) {
            X509CRLHolder crlHolder = new X509CRLHolder(bais);
            X509CRL crl = converter.getCRL(crlHolder);
            crls.add(crl);
        }

        return crls;
    }

    /**
     * Verifies a signature using the sub-filter adbe.pkcs7.detached or
     * adbe.pkcs7.sha1.
     *
     * @param contentsKey the /Contents key
     * @param provider    the provider or <code>null</code> for the default provider
     */
    public PdfPKCS7(byte[] contentsKey, String provider) {
        try {
            this.provider = provider;
            ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(contentsKey));

            //
            // Basic checks to make sure it's a PKCS#7 SignedData Object
            //
            ASN1Primitive pkcs;

            try {
                pkcs = din.readObject();
            } catch (IOException e) {
                throw new IllegalArgumentException("can't decode PKCS7SignedData object");
            }
            if (!(pkcs instanceof ASN1Sequence)) {
                throw new IllegalArgumentException("Not a valid PKCS#7 object - not a sequence");
            }
            ASN1Sequence signedData = (ASN1Sequence) pkcs;
            ASN1ObjectIdentifier objId = (ASN1ObjectIdentifier) signedData.getObjectAt(0);
            if (!objId.getId().equals(ID_PKCS7_SIGNED_DATA))
                throw new IllegalArgumentException("Not a valid PKCS#7 object - not signed data");
//            ASN1Sequence content = (ASN1Sequence)((ASN1TaggedObject)signedData.getObjectAt(1)).getObject();
            ASN1TaggedObject tagged = (ASN1TaggedObject) signedData.getObjectAt(1);
            ASN1Sequence content = ASN1Sequence.getInstance(tagged, true);
            // the positions that we care are:
            //     0 - version
            //     1 - digestAlgorithms
            //     2 - possible ID_PKCS7_DATA
            //     (the certificates and crls are taken out by other means)
            //     last - signerInfos

            // the version
            version = ((ASN1Integer) content.getObjectAt(0)).getValue().intValue();

            // the digestAlgorithms
            digestalgos = new HashSet();
            Enumeration e = ((ASN1Set) content.getObjectAt(1)).getObjects();
            while (e.hasMoreElements()) {
                ASN1Sequence s = (ASN1Sequence) e.nextElement();
                ASN1ObjectIdentifier o = (ASN1ObjectIdentifier) s.getObjectAt(0);
                digestalgos.add(o.getId());
            }

            // the certificates and crls
            crls = loadCrls(contentsKey);

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");
            ByteArrayInputStream in = new ByteArrayInputStream(contentsKey);

            while (in.available() > 0) {
                X509CertificateHolder holder = new X509CertificateHolder(Certificate.getInstance(in));
                certs.add(converter.getCertificate(holder));
            }

            // the possible ID_PKCS7_DATA
            ASN1Sequence rsaData = (ASN1Sequence) content.getObjectAt(2);

            if (rsaData.size() > 1) {
                ASN1TaggedObject t = (ASN1TaggedObject) rsaData.getObjectAt(1);
                DEROctetString rsaDataContent = (DEROctetString) ASN1OctetString.getInstance(t, true);
                RSAdata = rsaDataContent.getOctets();
            }

            // the signerInfos
            int next = 3;
            while (content.getObjectAt(next) instanceof ASN1TaggedObject)
                ++next;
            ASN1Set signerInfos = (ASN1Set) content.getObjectAt(next);
            if (signerInfos.size() != 1)
                throw new IllegalArgumentException("This PKCS#7 object has multiple SignerInfos - only one is supported at this time");
            ASN1Sequence signerInfo = (ASN1Sequence) signerInfos.getObjectAt(0);
            // the positions that we care are
            //     0 - version
            //     1 - the signing certificate serial number
            //     2 - the digest algorithm
            //     3 or 4 - digestEncryptionAlgorithm
            //     4 or 5 - encryptedDigest
            signerversion = ((ASN1Integer) signerInfo.getObjectAt(0)).getValue().intValue();
            // Get the signing certificate
            ASN1Sequence issuerAndSerialNumber = (ASN1Sequence) signerInfo.getObjectAt(1);
            BigInteger serialNumber = ((ASN1Integer) issuerAndSerialNumber.getObjectAt(1)).getValue();
            for (Iterator i = certs.iterator(); i.hasNext(); ) {
                X509Certificate cert = (X509Certificate) i.next();
                if (serialNumber.equals(cert.getSerialNumber())) {
                    signCert = cert;
                    break;
                }
            }
            if (signCert == null) {
                throw new IllegalArgumentException("Can't find signing certificate with serial " + serialNumber.toString(16));
            }
            signCertificateChain();
            digestAlgorithm = ((ASN1ObjectIdentifier) ((ASN1Sequence) signerInfo.getObjectAt(2)).getObjectAt(0)).getId();
            next = 3;
            if (signerInfo.getObjectAt(next) instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagsig = (ASN1TaggedObject) signerInfo.getObjectAt(next);
                ASN1Set sseq = ASN1Set.getInstance(tagsig, false);
                sigAttr = sseq.getEncoded(ASN1Encoding.DER);

                for (int k = 0; k < sseq.size(); ++k) {
                    ASN1Sequence seq2 = (ASN1Sequence) sseq.getObjectAt(k);
                    if (((ASN1ObjectIdentifier) seq2.getObjectAt(0)).getId().equals(ID_MESSAGE_DIGEST)) {
                        ASN1Set set = (ASN1Set) seq2.getObjectAt(1);
                        digestAttr = ((DEROctetString) set.getObjectAt(0)).getOctets();
                    } else if (((ASN1ObjectIdentifier) seq2.getObjectAt(0)).getId().equals(ID_ADBE_REVOCATION)) {
                        ASN1Set setout = (ASN1Set) seq2.getObjectAt(1);
                        ASN1Sequence seqout = (ASN1Sequence) setout.getObjectAt(0);
                        for (int j = 0; j < seqout.size(); ++j) {
                            ASN1Encodable obj = seqout.getObjectAt(j);
                            if (!(obj instanceof ASN1TaggedObject))
                                continue;

                            ASN1TaggedObject tg = (ASN1TaggedObject) obj;

                            if (tg.getTagNo() != 1)
                                continue;

                            ASN1Sequence seqin = ASN1Sequence.getInstance(tg, true); // Explicit tag
                            findOcsp(seqin);
                        }
                    }
                }
                if (digestAttr == null)
                    throw new IllegalArgumentException("Authenticated attribute is missing the digest.");
                ++next;
            }
            digestEncryptionAlgorithm = ((ASN1ObjectIdentifier) ((ASN1Sequence) signerInfo.getObjectAt(next++)).getObjectAt(0)).getId();
            digest = ((DEROctetString) signerInfo.getObjectAt(next++)).getOctets();
            if (next < signerInfo.size() && (signerInfo.getObjectAt(next) instanceof ASN1TaggedObject taggedObject)) {
                ASN1Set unat = ASN1Set.getInstance(taggedObject, false);  // usually implicit tag
                AttributeTable attble = new AttributeTable(unat);
                Attribute ts = attble.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                if (ts != null) {
                    ASN1Set attributeValues = ts.getAttrValues();
                    ASN1Sequence tokenSequence = ASN1Sequence.getInstance(attributeValues.getObjectAt(0));
                    ContentInfo contentInfo = ContentInfo.getInstance(tokenSequence);
                    this.timeStampToken = new TimeStampToken(contentInfo);
                }
            }
            if (RSAdata != null || digestAttr != null) {
                if (provider == null || provider.startsWith("SunPKCS11"))
                    messageDigest = MessageDigest.getInstance("SHA-256"); // 🔁 replaced getHashAlgorithm()
                else
                    messageDigest = MessageDigest.getInstance("SHA-256", provider);
            }

            if (provider == null)
                sig = Signature.getInstance("SHA256withRSA"); // 🔁 replaced getDigestAlgorithm()
            else
                sig = Signature.getInstance("SHA256withRSA", provider);

            sig.initVerify(signCert.getPublicKey());
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }
    /**
     * Generates a signature.
     * @param privKey the private key
     * @param certChain the certificate chain
     * @param crlList the certificate revocation list
     * @param hashAlgorithm the hash algorithm
     * @param provider the provider or <code>null</code> for the default provider
     * @param hasRSAdata <CODE>true</CODE> if the sub-filter is adbe.pkcs7.sha1
     * @throws InvalidKeyException on error
     * @throws NoSuchProviderException on error
     * @throws NoSuchAlgorithmException on error
     */
    public PdfPKCS7(PrivateKey privKey, java.security.cert.Certificate[] certChain, CRL[] crlList,
                    String hashAlgorithm, String provider, boolean hasRSAdata)
            throws InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException
    {
        this.privKey = privKey;
        this.provider = provider;

        digestAlgorithm = (String)allowedDigests.get(hashAlgorithm.toUpperCase());
        if (digestAlgorithm == null)
            throw new NoSuchAlgorithmException("Unknown Hash Algorithm "+hashAlgorithm);

        version = signerversion = 1;
        certs = new ArrayList();
        crls = new ArrayList();
        digestalgos = new HashSet();
        digestalgos.add(digestAlgorithm);

        //
        // Copy in the certificates and crls used to sign the private key.
        //
        signCert = (X509Certificate)certChain[0];
        for (int i = 0;i < certChain.length;i++) {
            certs.add(certChain[i]);
        }

        if (crlList != null) {
            for (int i = 0;i < crlList.length;i++) {
                crls.add(crlList[i]);
            }
        }

        if (privKey != null) {
            //
            // Now we have private key, find out what the digestEncryptionAlgorithm is.
            //
            digestEncryptionAlgorithm = privKey.getAlgorithm();
            if (digestEncryptionAlgorithm.equals("RSA")) {
                digestEncryptionAlgorithm = ID_RSA;
            }
            else if (digestEncryptionAlgorithm.equals("DSA")) {
                digestEncryptionAlgorithm = ID_DSA;
            }
            else {
                throw new NoSuchAlgorithmException("Unknown Key Algorithm "+digestEncryptionAlgorithm);
            }
        }
        if (hasRSAdata) {
            RSAdata = new byte[0];
            if (provider == null || provider.startsWith("SunPKCS11"))
                messageDigest = MessageDigest.getInstance("SHA-256");
            else
                messageDigest = MessageDigest.getInstance("SHA-256", provider);
        }

        if (privKey != null) {
            if (provider == null)
                sig = Signature.getInstance("SHA256withRSA"); // 🔁 replaced getDigestAlgorithm()
            else
                sig = Signature.getInstance("SHA256withRSA", provider);

            sig.initSign(privKey);
        }
    }

    /**
     * Update the digest with the specified bytes. This method is used both for signing and verifying
     * @param buf the data buffer
     * @param off the offset in the data buffer
     * @param len the data length
     * @throws SignatureException on error
     */
    public void update(byte[] buf, int off, int len) throws SignatureException {
        if (RSAdata != null || digestAttr != null)
            messageDigest.update(buf, off, len);
        else
            sig.update(buf, off, len);
    }

    /**
     * Verify the digest.
     * @throws SignatureException on error
     * @return <CODE>true</CODE> if the signature checks out, <CODE>false</CODE> otherwise
     */
    public boolean verify() throws SignatureException {
        if (verified)
            return verifyResult;
        if (sigAttr != null) {
            sig.update(sigAttr);
            if (RSAdata != null) {
                byte msd[] = messageDigest.digest();
                messageDigest.update(msd);
            }
            verifyResult = (Arrays.equals(messageDigest.digest(), digestAttr) && sig.verify(digest));
        }
        else {
            if (RSAdata != null)
                sig.update(messageDigest.digest());
            verifyResult = sig.verify(digest);
        }
        verified = true;
        return verifyResult;
    }

    /**
     * Checks if the timestamp refers to this document.
     * @throws java.security.NoSuchAlgorithmException on error
     * @return true if it checks false otherwise
     * @since	2.1.6
     */
    public boolean verifyTimestampImprint() throws NoSuchAlgorithmException {
        if (timeStampToken == null)
            return false;
        MessageImprint imprint = timeStampToken.getTimeStampInfo().toASN1Structure().getMessageImprint();
        byte[] md = MessageDigest.getInstance("SHA-1").digest(digest);
        byte[] imphashed = imprint.getHashedMessage();
        return Arrays.equals(md, imphashed);
    }

    /**
     * Get all the X.509 certificates associated with this PKCS#7 object in no particular order.
     * Other certificates, from OCSP for example, will also be included.
     * @return the X.509 certificates associated with this PKCS#7 object
     */
    public java.security.cert.Certificate[] getCertificates() {
        return (X509Certificate[])certs.toArray(new X509Certificate[0]);
    }

    /**
     * Get the X.509 sign certificate chain associated with this PKCS#7 object.
     * Only the certificates used for the main signature will be returned, with
     * the signing certificate first.
     * @return the X.509 certificates associated with this PKCS#7 object
     * @since	2.1.6
     */
    public java.security.cert.Certificate[] getSignCertificateChain() {
        return (X509Certificate[])signCerts.toArray(new X509Certificate[0]);
    }

    private void signCertificateChain() {
        var cc = new ArrayList<>();
        cc.add(signCert);
        var oc = new ArrayList<>(certs);
        for (int k = 0; k < oc.size(); ++k) {
            if (signCert.getSerialNumber().equals(((X509Certificate)oc.get(k)).getSerialNumber())) {
                oc.remove(k);
                --k;
                continue;
            }
        }
        boolean found = true;
        while (found) {
            X509Certificate v = (X509Certificate)cc.getLast();
            found = false;
            for (int k = 0; k < oc.size(); ++k) {
                try {
                    if (provider == null)
                        v.verify(((X509Certificate)oc.get(k)).getPublicKey());
                    else
                        v.verify(((X509Certificate)oc.get(k)).getPublicKey(), provider);
                    found = true;
                    cc.add(oc.get(k));
                    oc.remove(k);
                    break;
                }
                catch (Exception ignored) {}
            }
        }
        signCerts = cc;
    }
}