package org.bxjiang.jwtsample;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;

import java.io.UnsupportedEncodingException;

public class JwtSample {
    private static final String SUBJECT_ID = "c8bw1hcoxk84mgtk20ftgxww3946krbc";
    private static final String SECRET_KEY = "bhvkcl7xn8c4aewgg6y25dz54ankz2pv";

    public static void main(String... args) throws UnsupportedEncodingException {
        String requestBody = "{\n" +
                "  \"eid\": \"89001012012341234012345678901224\",\n" +
                "  \"iccid\": \"89852245284000011257\"\n" +
                "}";
        // Sign
        String token = sign(requestBody, SUBJECT_ID, SECRET_KEY);

        // Verify
        verify(token, requestBody, SUBJECT_ID, SECRET_KEY);
    }

    static String sign(String requestBody, String subjectId, String secretKey) throws UnsupportedEncodingException {
        String requestBodyHash = sha256(requestBody);
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        return JWT.create().withSubject(subjectId)
                .withClaim("timestamp", String.valueOf(System.currentTimeMillis()))
                .withClaim("hash", requestBodyHash)
                .sign(algorithm);
    }

    static void verify(String token, String requestBody, String subjectId, String secretKey) throws UnsupportedEncodingException {
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        JWTVerifier verifier = JWT.require(algorithm)
                .withSubject(subjectId)
                .build();
        verifier.verify(token);
        JWT decodedToken = JWT.decode(token);
        Claim timestampClaim = decodedToken.getClaim("timestamp");
        if (timestampClaim.isNull()) {
            throw new JWTVerificationException("timestamp field is required in JWT payload");
        }
        long timestamp = Long.parseLong(timestampClaim.asString());
        if (System.currentTimeMillis() - timestamp > 5000) {
            throw new JWTVerificationException("Timestamp is far away from now");
        }
        Claim hashClaim = decodedToken.getClaim("hash");
        if (hashClaim.isNull()) {
            throw new JWTVerificationException("hash field is required in JWT payload");
        }
        String hash = hashClaim.asString();
        if (!sha256(requestBody).equalsIgnoreCase(hash)) {
            throw new JWTVerificationException("hash field of JWT payload is not the sha256 of request body");
        }
        System.out.println("Verified OK");
    }

    static String sha256(String requestBody) {
        return Hashing.sha256().hashString(requestBody, Charsets.UTF_8).toString();
    }
}
