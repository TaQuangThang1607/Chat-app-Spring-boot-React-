package com.example.Chap.utils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.example.Chap.model.dto.ResponseUserLogin;
import com.nimbusds.jose.util.Base64;

@Service
public class SecurityUtil {
    public static final MacAlgorithm JWT_ALGROITHM = MacAlgorithm.HS512;

    private final JwtEncoder jwtEncoder;
    
    @Value("${jwt.base64.secret}")
    private String jwtKey;

    @Value("${jwt.access-token-validity-in-seconds}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.token-validity-in-seconds}")
    private long refreshTokenExpiration;

    

    public SecurityUtil(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }



    public String createAccessToken(String email, ResponseUserLogin.UserLogin loginUser){
        Instant now = Instant.now();
        Instant validaty = now.plus(this.accessTokenExpiration, ChronoUnit.SECONDS);
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
        .issuedAt(now)
        .expiresAt(validaty)
        .subject(email)
        .claim("user", loginUser)
        .build();

        JwsHeader header = JwsHeader.with(JWT_ALGROITHM).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header,  claimsSet)).getTokenValue();
    }

    public String createRefreshToken(String email, ResponseUserLogin loginUser){
        Instant now = Instant.now();
        Instant validaty = now.plus(this.refreshTokenExpiration, ChronoUnit.SECONDS);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
        .issuedAt(now)
        .expiresAt(validaty)
        .subject(email)
        .claim("user", loginUser)
        .build();
        
        JwsHeader jwsHeader = JwsHeader.with(JWT_ALGROITHM).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsSet)).getTokenValue();
    }

    public Jwt checkValidRefreshToken(String token){
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(
                getSecretKey()).macAlgorithm(SecurityUtil.JWT_ALGROITHM).build();
            try {
                return jwtDecoder.decode(token);

            } catch (Exception e) {
                System.out.println(">>> Refreesh Token error: " + e.getMessage());
                throw e;
            }
    }
    private SecretKey getSecretKey(){
        byte[] keyBytes = Base64.encode(jwtKey).decode();
        return new SecretKeySpec(keyBytes, 0,keyBytes.length, 
           JWT_ALGROITHM.getName());
    }
    private static String extractPrincipal(Authentication authentication) {
        if (authentication == null) {
            return null;
        } else if (authentication.getPrincipal() instanceof UserDetails springSecurityUser) {
            return springSecurityUser.getUsername();
        } else if (authentication.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        } else if (authentication.getPrincipal() instanceof String s) {
            return s;
        }
        return null;
    }
    
    public static Optional<String> getCurrentUserJWT() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(securityContext.getAuthentication())
            .filter(authentication -> authentication.getCredentials() instanceof String)
            .map(authentication -> (String) authentication.getCredentials());
    }

    public static Optional<String> getCurrentUserLogin() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(extractPrincipal(securityContext.getAuthentication()));
    }

    /**
     * Checks if the current user has any of the authorities.
     *
     * @param authorities the authorities to check.
     * @return true if the current user has any of the authorities, false otherwise.
     */
    public static boolean hasCurrentUserAnyOfAuthorities(String... authorities) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (
            authentication != null && getAuthorities(authentication).anyMatch(authority -> Arrays.asList(authorities).contains(authority))
        );
    }

/**
     * Checks if the current user has none of the authorities.
     *
     * @param authorities the authorities to check.
     * @return true if the current user has none of the authorities, false otherwise.
     */
    public static boolean hasCurrentUserNoneOfAuthorities(String... authorities) {
        return !hasCurrentUserAnyOfAuthorities(authorities);
    }

    /**
     * Checks if the current user has a specific authority.
     *
     * @param authority the authority to check.
     * @return true if the current user has the authority, false otherwise.
     */
    public static boolean hasCurrentUserThisAuthority(String authority) {
        return hasCurrentUserAnyOfAuthorities(authority);
    }

    private static Stream<String> getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority);
    }
}
