package certificatemanager;



import java.security.KeyPair;

public class CertificateManager {
    public static void main(String[] args) throws Exception {
        DigitalCertificate certificate = new DigitalCertificate();
        System.out.println(certificate.certificate.toString());

        String issuedAlgo = "RSA";
        String bcProvider = "BC";
        String algo = "EC";
        String signatureAlgo = "";

        if (algo.equals("RSA")) signatureAlgo = "SHA256withRSA";
        else if (algo.equals("EC")) signatureAlgo = "SHA256withECDSA";

        GenerateKey key = new GenerateKey(algo); //valuenya bisa RSA atau EC
        GenerateKey issuedKey = new GenerateKey(issuedAlgo);
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
