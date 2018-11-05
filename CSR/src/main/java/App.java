import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.UUID;

public class App {
    public static KeyPair keyPair;
    public static final UUID uuid = UUID.fromString("09567082-faa4-4ed1-8784-0815c9d63484");

    public static void main(String[] args) throws Exception {
        createKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + uuid.toString()), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());

        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement);
        ExtensionsGenerator exgen = new ExtensionsGenerator();
        exgen.addExtension(Extension.keyUsage, true, usage);
        exgen.addExtension(Extension.subjectKeyIdentifier, true, new SubjectKeyIdentifier(keyPair.getPublic().getEncoded()));
        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, exgen.generate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        System.out.println(new String(Base64.getEncoder().encodeToString(csr.getEncoded())));
    }

    private static void createKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec kpgparams = new ECGenParameterSpec("secp256r1");
        generator.initialize(kpgparams);
        keyPair = generator.generateKeyPair();
        System.out.println(keyPair.getPublic());
    }
}