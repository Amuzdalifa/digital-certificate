package certificatemanager;


public class CertificateManager {
    public static void main(String[] args) throws Exception {
        DigitalCertificate certificate = new DigitalCertificate();
        System.out.println(certificate.certificate.toString());
    }
}
