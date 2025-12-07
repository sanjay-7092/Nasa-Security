package com.nasa.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import java.util.Date;

public class JWTUtil {

    @Value("${security-key}")
    private static String securityKey ;

    private static final SecretKey key = Keys.hmacShaKeyFor(securityKey.getBytes());

    public static String generateToken(String userName){
       return Jwts.builder()
               .setSubject(userName)
               .setIssuedAt(new Date())
               .setExpiration(new Date(System.currentTimeMillis()+1000*60*80))
               .signWith(key, SignatureAlgorithm.HS256)
               .compact();
    }

    public static String extractUserName(String token){
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
}
