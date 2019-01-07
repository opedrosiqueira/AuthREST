package authrest;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class AutenticacaoPropriedades {

    private String issuer;
    private long expiresAfter;
    private Key key;

    @PostConstruct
    public void init() {
        try {
//          InputStream inputStream = getClass().getClassLoader().getResourceAsStream("autenticacao.properties"); //alternativa
            InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("auth.properties"); //alternativa
            Properties appProps = new Properties();
            appProps.load(inputStream);

            this.issuer = appProps.getProperty("jwt.issuer", "MavenREST");
            this.expiresAfter = Long.parseLong(appProps.getProperty("jwt.expirationTime", "90000"));
            this.key = new SecretKeySpec(Base64.getDecoder().decode(appProps.getProperty("jwt.secret", "sBVv63uLzY0YfmzbfjamgTbCSdHTXqf3epish834khU=")), "HmacSHA256");
//          this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(ap.getSecret())); //alternativa usando biblioteca jjwt

        } catch (FileNotFoundException ex) {
            Logger.getLogger(AutenticacaoPropriedades.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AutenticacaoPropriedades.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public Key getKey() {
        return key;
    }

    public String getIssuer() {
        return issuer;
    }

    public long getExpiresAfter() {
        return expiresAfter;
    }
}
