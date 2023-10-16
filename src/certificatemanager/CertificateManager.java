package certificatemanager;



import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.extension.X509ExtensionUtil;


import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CertificateManager {
    public static void main(String[] args) throws Exception {
        CertificateAuthority certificateAuthority = new CertificateAuthority("CN=BankIndonesia, O=o, L=L, ST=il, C=c");

        String issuedAlgo = "RSA";
        String bcProvider = "BC";
        String algo = "RSA";
        String signatureAlgo;

        if (algo.equals("RSA")) signatureAlgo = "SHA256withRSA";
        else if (algo.equals("EC")) signatureAlgo = "SHA256withECDSA";
        signatureAlgo = "SHA256withRSA";

        SelfKeyGenerator key = new SelfKeyGenerator(algo); //valuenya bisa RSA atau EC
        CSRCreator csrCreator = new CSRCreator(key.keyPair, signatureAlgo, bcProvider);
        PKCS10CertificationRequest csr = csrCreator.csr;

//        csrCreator.writeToFile();
        System.out.println(Arrays.stream(csr.getAttributes()));
        X509Certificate issuedCert = certificateAuthority.SignCSR(csr);

        System.out.println(issuedCert.getPublicKey());
//        System.out.println(verifyCertificate("message", issuedCert, key.keyPair.getPrivate()));

        certificateAuthority.writeToFile(issuedCert);

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.9");
        byte[] v = issuedCert.getExtensionValue(Extension.subjectAlternativeName.getId());
        GeneralNames gn = GeneralNames.getInstance(X509ExtensionUtil.fromExtensionValue(v));
        GeneralName[] names = gn.getNames();
        for (GeneralName name : names) {
            if (name.getTagNo() == GeneralName.otherName) {
                ASN1Sequence seq = ASN1Sequence.getInstance(name.getName());
                if ("1.2.3.4.5.6.7.8.9".equals(oid.getId())) { // OID is the arbitrary one I created
                    DERPrintableString value = (DERPrintableString) seq.getObjectAt(1);
                    String paymentId = value.getString();
                    System.out.println(paymentId); // number is 123
                }
            }
        }
    }

    public static Boolean verifyCertificate(String message, X509Certificate cert, PrivateKey privateKey) throws Exception {
        byte[] byteMessage = message.getBytes(StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance(cert.getSigAlgName());
        sig.initSign(privateKey);
        sig.update(byteMessage);
        byte[] signatureBytes = sig.sign();

        sig.initVerify(cert.getPublicKey());
        sig.update(byteMessage);
        return sig.verify(signatureBytes);
    }
}
