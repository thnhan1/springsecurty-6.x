package com.nhan.aop.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

  private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

  @Value("${app.jwtSecret}")
  private String jwtSecret;

  @Value("${app.jwtExpirationInMs}")
  private int jwtExpirationInMs;

  private SecretKey getSigningKey() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public String generateToken(Authentication authentication) {
    UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

    SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

    return Jwts.builder()
        .subject(userPrincipal.getUsername())
        .issuedAt(now)
        .expiration(expiryDate)
        .signWith(getSigningKey())
        .compact();
  }

  public String getUsernameFromJWT(String token) {
    return Jwts.parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getSubject(); // subject = username
  }

  public boolean validateToken(String authToken) {
    try {
      Jwts.parser()
          .verifyWith(getSigningKey())
          .build()
          .parseSignedClaims(authToken);
      return true;
    } catch (SignatureException e) {
      System.err.println("Invalid JWT signature: " + e.getMessage());
    } catch (ExpiredJwtException e) {
      System.err.println("Expired JWT token: " + e.getMessage());
    } catch (MalformedJwtException e) {
      System.err.println("Invalid JWT token format: " + e.getMessage());
    } catch (Exception e) {
      System.err.println("Invalid JWT token: " + e.getMessage());
    }
    return false;
  }
}
