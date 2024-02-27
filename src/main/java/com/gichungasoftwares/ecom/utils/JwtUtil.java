package com.gichungasoftwares.ecom.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {
    public static final String SECRET = "413F4428472B4B6250655368566D5970337336763979244226452948404D6351";

    public String generateToken(String username){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    public String createToken(Map<String, Object> claims, String username){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    //return signing key in base64 format
    private Key getSignKey(){
        byte[] keybytes = Decoders.BASE64.decode(SECRET);
        //format the key and return it
        return Keys.hmacShaKeyFor(keybytes);
    }

    //method to extract username from token
    public String extractUsernameFromToken(String token){
        return extractClaim(token, Claims::getSubject);
    }

    //extract claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractClaims(token);
        return claimsResolver.apply(claims);
    }

    //extract all claims
    private Claims extractClaims(String token){
        return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
    }

    // method to check the expiration of json web tokens (jwt)
    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    //implementation of the extract expiration
    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    //method to validate our token
    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = extractUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
