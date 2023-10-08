package certificatemanager;



import java.security.KeyPair;

public class CertificateManager {
    public static void main(String[] args) throws Exception {
        DigitalCertificate certificate = new DigitalCertificate();
        System.out.println(certificate.certificate.toString());
        String algo = "RSA";
        String signatureAlgo = "SHA256withRSA";
        String bcProvider = "BC";


        GenerateKey key = new GenerateKey(algo); //valuenya bisa RSA atau ECDSA
        GenerateKey issuedKey = new GenerateKey(algo); //valuenya bisa RSA atau ECDSA
        System.out.println("testing Generate key ...");
        System.out.println("Algorithm = " + key.algorithm.toString());
        System.out.println("private= "+key.keyPair.getPrivate().toString());
        System.out.println("public= "+key.keyPair.getPublic().toString());

        KeyPair keyPair = new KeyPair(key.keyPair.getPublic(),key.keyPair.getPrivate());
        KeyPair issuedKeyPair = new KeyPair(issuedKey.keyPair.getPublic(),issuedKey.keyPair.getPrivate());

        CreateCSR createCSR = new CreateCSR();
        createCSR.CreateCSR(keyPair,signatureAlgo,bcProvider,issuedKeyPair);


    }
}
