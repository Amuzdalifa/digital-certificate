package certificatemanager;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SelfKeyGenerator {
    public String algorithm;
    public KeyPair keyPair;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SelfKeyGenerator(String algo) {
        try {
            //Create KeyGenerator object and choose the algorithm
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo);
            this.algorithm = algo;

            //Set the keysize
            if ("RSA".equals(algo)) {
                keyGen.initialize(2048);
            } else if ("EC".equals(algo)) {
                ECGenParameterSpec curve = new ECGenParameterSpec("secp224k1");
                keyGen.initialize(curve);
            } else {
                throw new NoSuchAlgorithmException();
            }

            //Generate the keypair
            this.keyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException err) {
            System.out.println(algo + " algorithm could not be found... Please use RSA or EC");
        }
    }
}
