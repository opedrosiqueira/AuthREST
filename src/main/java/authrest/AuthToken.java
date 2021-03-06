package authrest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.util.Date;
import javax.inject.Inject;

public class AuthToken {

    @Inject
    AuthProperties ap;

    @Inject
    AuthDAO adao;

    public String buildToken(String subject, String senha) {
        Date dateIssued = new Date();
        Date dateExpires = new Date(dateIssued.getTime() + ap.getExpiresAfter());
        return Jwts.builder()
                .setIssuer(ap.getIssuer())
                .setSubject(subject)
                .setIssuedAt(dateIssued)
                .setExpiration(dateExpires)
                .signWith(ap.getKey())
                .compact();
    }

    public String getSubject(String token) {
        Jws<Claims> claims = Jwts.parser().setSigningKey(ap.getKey()).parseClaimsJws(token);
        return claims.getBody().getSubject();
    }

    public String getToken(String email, String senha) {
        AuthUser u = adao.getSubject(email);
        if (u == null || !AuthHash.equals(senha, u.getSalt(), u.getPassword())) {
            throw new javax.ws.rs.ForbiddenException("usuario ou senha incorreta");
        }
        return buildToken(email, senha);
    }
}
