package certificatemanager;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class CSRCreator {
    public PKCS10CertificationRequest csr;
    public String signAlgo;
    public String bcProvider;

    public CSRCreator(KeyPair keyPair, String algorithm, String bcProvider) {
        this.signAlgo = algorithm;
        this.bcProvider = bcProvider;
        try {
            this.CreateCSR(keyPair, this.signAlgo, this.bcProvider);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("deprecation")
    public void CreateCSR(KeyPair keyPair, String algorithm, String bcProvider) throws Exception {

        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Alice"), keyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(algorithm).setProvider(bcProvider);
        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(keyPair.getPrivate());
        this.csr = p10Builder.build(csrContentSigner);
    }

    public void writeToFile() throws IOException {
        //Write file
        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new FileWriter("cert/test2.csr"));
        jcaPEMWriter.writeObject(this.csr);
        jcaPEMWriter.close();
    }

}
