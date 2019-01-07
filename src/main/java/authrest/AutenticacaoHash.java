package authrest;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author pedro
 */
public class AutenticacaoHash {

    /**
     * converte a senha e o salt para um hash e o compara com outro hash
     */
    public static boolean igual(String senha, String salt, String hash) {
        try {
            senha = gerarHash(senha, salt);
            return hash.equals(senha);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            return false;
        }
    }

    /**
     * gera o hash a partir da senha e do salt
     */
    public static String gerarHash(String senha, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec pks = new PBEKeySpec(senha.toCharArray(), Base64.getDecoder().decode(salt), 65536, 128);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(pks).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * gera um salt aleatorio
     */
    public static String gerarSaltAleatorio() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

}
