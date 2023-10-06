package certificatemanager;

import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerateKey {
    public String algorithm;
    public KeyPair keyPair;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public GenerateKey(String algo) {
        try {
            //Create KeyGenerator object and choose the algorithm
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo);
            this.algorithm = algo;

            //Set the keysize
            if ("RSA".equals(algo)) {
                keyGen.initialize(2048);
            } else if ("ECDSA".equals(algo)) {
                keyGen.initialize(224);
            } else {
                throw new NoSuchAlgorithmException();
            }

            //Generate the keypair
            this.keyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException err) {
            System.out.println(algo + " algorithm could not be found... Please use RSA or ECDSA");
        }
    }
}
