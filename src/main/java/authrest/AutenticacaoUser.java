package authrest;

import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.InvalidKeySpecException;
import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;
import javax.validation.constraints.NotEmpty;
import static authrest.AutenticacaoHash.gerarHash;
import static authrest.AutenticacaoHash.gerarSaltAleatorio;

@MappedSuperclass
public class AutenticacaoUser implements Principal {

    @Id
    @GeneratedValue
    private long id;

    @Column(nullable = false)
    @NotEmpty
    private String name;

    @Column(nullable = false)
    private String password;

    private String salt;

    private String role;

    public AutenticacaoUser() {
    }

    public AutenticacaoUser(String name, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.setPassword(password);
        this.name = name;
    }

    public AutenticacaoUser(String name, String password, String role) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.setPassword(password);
        this.name = name;
        this.role = role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.salt = gerarSaltAleatorio();
        this.password = gerarHash(password, salt);
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }
}
