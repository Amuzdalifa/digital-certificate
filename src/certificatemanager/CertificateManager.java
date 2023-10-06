package certificatemanager;


import java.security.KeyPair;

public class CertificateManager {
    public static void main(String[] args) throws Exception {
        DigitalCertificate certificate = new DigitalCertificate();
        System.out.println(certificate.certificate.toString());

        GenerateKey key = new GenerateKey("RSA"); //valuenya bisa RSA atau ECDSA
        System.out.println("testing Generate key ...");
        System.out.println("Algorithm = " + key.algorithm.toString());
        System.out.println(key.keyPair.getPrivate().toString());
        System.out.println(key.keyPair.getPublic().toString());
    }
}
