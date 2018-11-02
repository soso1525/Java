import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class App {
	private static final String SECRET_KEY = "MytownWebServer";

	public static void main(String[] args) throws Exception {
		System.out.println(makeJwt());
		checkJwt(makeJwt());
	}

	private static String makeJwt() {
		SignatureAlgorithm algorithm = SignatureAlgorithm.HS256;
		Date expireTime = new Date();
		expireTime.setTime(expireTime.getTime() + 1000 * 60 * 60);
		byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
		Key signingKey = new SecretKeySpec(apiKeySecretBytes, algorithm.getJcaName());

		Map<String, Object> header = new HashMap<>();
		header.put("typ", "JWT");
		header.put("alg", "HS256");

		Map<String, Object> payload = new HashMap<>();
		payload.put("id", "admin");
		payload.put("password", "비밀번호");

		JwtBuilder builder = Jwts.builder().setHeader(header).setClaims(payload).setExpiration(expireTime)
				.signWith(algorithm, signingKey);
		return builder.compact();
	}

	private static void checkJwt(String jwt) throws Exception {
		Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY)).parseClaimsJws(jwt)
				.getBody();
		System.out.println(claims.get("id"));
		System.out.println(claims.get("password"));
	}
}
