package authrest;

import java.security.Principal;
import javax.ws.rs.core.SecurityContext;

/**
 *
 * @author pedro
 */
public class AuthContext implements SecurityContext {

    private final AuthUser au;
    private final boolean isSecure;
    private final String authenticationScheme;

    public AuthContext(AuthUser u, boolean isSecure, String authenticationScheme) {
        this.au = u;
        this.isSecure = isSecure;
        this.authenticationScheme = authenticationScheme;
    }

    @Override
    public Principal getUserPrincipal() {
        return au;
    }

    @Override
    public boolean isUserInRole(String role) {
        if (role == null || role.isEmpty()) {
            return au.getRole() == null || au.getRole().isEmpty();
        }
        return role.equalsIgnoreCase(au.getRole());
    }

    @Override
    public boolean isSecure() {
        return isSecure;
    }

    @Override
    public String getAuthenticationScheme() {
        return authenticationScheme;
    }

}
