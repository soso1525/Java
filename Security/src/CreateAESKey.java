import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;

public class CreateAESKey {
	public static void main(String[] args) {
		try {
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			generator.init(128, random);
			Key secureKey = generator.generateKey();
			byte[] encodedKey = Base64.getEncoder().encode(secureKey.getEncoded());
			System.out.println(new String(encodedKey));
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
	}
}
