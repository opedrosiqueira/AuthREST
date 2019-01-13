package authrest;

import io.jsonwebtoken.JwtException;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

@Auth
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthFilter implements ContainerRequestFilter {

    @Inject
    AuthToken at;

    @Inject
    AuthDAO subjectDAO;

    @Context
    private ResourceInfo ri;

    @Override
    public void filter(ContainerRequestContext req) {
        String token = req.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer")) {
            req.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("Esquema de autenticacao invalido ou inexistente").build());
            return;
        }
        token = token.substring(7);
        try {
            AuthUser u = subjectDAO.getSubject(at.getSubject(token));
            if (u == null) {
                req.abortWith(Response.status(Response.Status.FORBIDDEN).entity("usuario ou senha incorreta").build());
                return;
            }
            boolean isSecure = "https".equalsIgnoreCase(req.getUriInfo().getRequestUri().getScheme());
            AuthContext seq = new AuthContext(u, isSecure, "Bearer");
            req.setSecurityContext(seq);
            for (String role : ri.getResourceMethod().getAnnotation(Auth.class).value()) {
                if (seq.isUserInRole(role) || role == null || role.isEmpty()) {
                    return;
                }
            }
            req.abortWith(Response.status(Response.Status.FORBIDDEN).entity("Sem permissão").build());
        } catch (JwtException e) {
            req.abortWith(Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build());
        } catch (Exception e) {
            req.abortWith(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build());
        }
    }
}
