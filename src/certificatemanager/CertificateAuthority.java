package certificatemanager;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;


public class CertificateAuthority {

    public X509Certificate rootCertificate;
    public KeyPair rootKeyPair;
    public X509Principal issuer;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @SuppressWarnings("deprecation")
    public CertificateAuthority(String issuer) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        this.rootKeyPair = new SelfKeyGenerator("RSA").keyPair;

        //Generate Self Sign Certificate
        X509V3CertificateGenerator certGen3 = new X509V3CertificateGenerator();
        certGen3.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        this.issuer = new X509Principal(issuer);
        certGen3.setIssuerDN(this.issuer);
        certGen3.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        certGen3.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
        certGen3.setSubjectDN(new X500Principal("CN=BankIndonesia, O=o, L=L, ST=il, C=c"));
        certGen3.setPublicKey(this.rootKeyPair.getPublic());
        certGen3.setSignatureAlgorithm("SHA256WithRSA");

        this.rootCertificate = certGen3.generateX509Certificate(this.rootKeyPair.getPrivate());

    }

    public X509Certificate SignCSR(PKCS10CertificationRequest csr) throws Exception {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        AlgorithmIdentifier signingAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");
        AlgorithmIdentifier digestAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(signingAlgId);
        AsymmetricKeyParameter caPrivateKeyParameter = PrivateKeyFactory.createKey(rootKeyPair.getPrivate().getEncoded());
        ContentSigner contentSigner = new BcRSAContentSignerBuilder(signingAlgId, digestAlgId).build(caPrivateKeyParameter);

        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(new X500Name(this.issuer.getName()), issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCertificate));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        ASN1EncodableVector paymentId = new ASN1EncodableVector();
        paymentId.add(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.9"));
        paymentId.add(new DERPrintableString("7708321910102"));
        DERSequence paymentIdATV = new DERSequence(paymentId);

        ArrayList<GeneralName> namesList = new ArrayList<>();
        namesList.add(new GeneralName(GeneralName.otherName, paymentIdATV));
        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence(namesList.toArray(new GeneralName[] {})));

        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(contentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider("BC").getCertificate(issuedCertHolder);

        return issuedCert;
    }
    
    public void writeToFile(X509Certificate cert) throws IOException {
        //Write file
        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new FileWriter("cert/cert.pem"));
        jcaPEMWriter.writeObject(cert);
        jcaPEMWriter.close();
    }

}
