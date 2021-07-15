package com.trading.app.msauthentication.security;

import com.trading.app.msauthentication.constant.SecurityConstant;
import com.trading.app.msauthentication.entities.AlpacaCredentials;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.services.UserDetailsImp;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

import static com.trading.app.msauthentication.constant.SecurityConstant.JWT_PREFIX;


@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);


    private String jwtSecret = SecurityConstant.KEY;

    private Long jwtExpirationMs = SecurityConstant.EXPIRATION_TIME;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImp userPrincipal = (UserDetailsImp) authentication.getPrincipal();
        AlpacaCredentials alpacaCredentials = userPrincipal.getAlpacaCredentials();
        if (alpacaCredentials == null) alpacaCredentials = new AlpacaCredentials(null, "","" ,null);
        return  JWT_PREFIX + Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .claim("id", userPrincipal.getId())
                .claim("role", userPrincipal.getAuthorities().stream().findFirst().get().toString())
                .claim("alpacaKey", alpacaCredentials.getKey())
                .claim("alpacaSecret", alpacaCredentials.getSecret())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String generateJwtToken(User user) {
        AlpacaCredentials alpacaCredentials = user.getAlpacaCredentials();
        if (alpacaCredentials == null) alpacaCredentials = new AlpacaCredentials(null, "","" ,null);
        return  JWT_PREFIX + Jwts.builder()
                .setSubject(user.getUsername())
                .claim("id", user.getId())
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .claim("alpacaKey", alpacaCredentials.getKey())
                .claim("alpacaSecret", alpacaCredentials.getSecret())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

}
