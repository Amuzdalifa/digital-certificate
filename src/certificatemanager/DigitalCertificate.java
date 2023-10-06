package certificatemanager;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;


public class DigitalCertificate {

    public X509Certificate certificate;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @SuppressWarnings("deprecation")
    public DigitalCertificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //Generate Certificate
        X509V3CertificateGenerator certGen3 = new X509V3CertificateGenerator();
        certGen3.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen3.setIssuerDN(new X509Principal("CN=cn, O=o, L=L, ST=il, C=c"));
        certGen3.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        certGen3.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
        certGen3.setSubjectDN(new X500Principal("CN=cn, O=o, L=L, ST=il, C=c"));
        certGen3.setPublicKey(keyPair.getPublic());
        certGen3.setSignatureAlgorithm("SHA256WithRSAEncryption");

        this.certificate = certGen3.generateX509Certificate(keyPair.getPrivate());

    }
}
