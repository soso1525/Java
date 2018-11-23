import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

public class KeyGenerator {
	static ECPrivateKey privatekey = null;
	static ECPublicKey publicKey = null;
	static PublicKey pk = null;

	private static ECPrivateKey readPrivateKeyFromPemFile(String privateKeyName)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

		File initialFile = new File(privateKeyName);
		InputStream targetStream = new FileInputStream(initialFile);

		PEMParser pemParser = new PEMParser(new InputStreamReader(targetStream));
		PEMKeyPair kp = (PEMKeyPair) pemParser.readObject();

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		// PrivateKey ecKey = keyFactory.generatePrivate(new
		// PKCS8EncodedKeySpec(Base64.decode(keyBytes)));
		ECPrivateKey ecKey = (ECPrivateKey) keyFactory
				.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivateKeyInfo().getEncoded()));
		return ecKey;
	}

	private static ECPublicKey getPublickeyFromPrivatekey(ECPrivateKey privateKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

		// ECPoint Q = ecSpec.getG().multiply(privateKey.getS());
		ECPoint Q = ecSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD());

		ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
		PublicKey publicKeyGenerated = keyFactory.generatePublic(pubSpec);
		publicKey = (ECPublicKey) publicKeyGenerated;

		return publicKey;
	}

	private static PublicKey getCrt(String fileName) throws FileNotFoundException, CertificateException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		FileInputStream is = new FileInputStream(new File(fileName));
		X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
		System.out.println();
		System.out.println("====================== CERTIFICATE ======================");
		System.out.println("SerialNumber : " + cer.getSerialNumber());
		System.out.println("IssuerDN : " + cer.getIssuerDN().getName());
		System.out.println("NotBefore : " + cer.getNotBefore().toString());
		System.out.println("NotAfter : " + cer.getNotAfter().toString());
		System.out.println("SubjectDN : " + cer.getSubjectDN().getName());
		System.out.println("PublicKey : " + publicKey);
		System.out.println("SignatureAlgorithm : " + cer.getSigAlgName());

		PublicKey key = cer.getPublicKey();
		return key;
	}

}
