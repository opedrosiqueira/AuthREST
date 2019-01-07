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

@Autenticado
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AutenticacaoFiltro implements ContainerRequestFilter {

    @Inject
    AutenticacaoToken at;

    @Inject
    AutenticacaoDAO subjectDAO;

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
            AutenticacaoUser u = subjectDAO.getSubject(at.getSubject(token));
            boolean isSecure = "https".equalsIgnoreCase(req.getUriInfo().getRequestUri().getScheme());
            AutenticacaoContext seq = new AutenticacaoContext(u, isSecure, "Bearer");
            req.setSecurityContext(seq);
            for (String role : ri.getResourceMethod().getAnnotation(Autenticado.class).value()) {
                if (seq.isUserInRole(role) || role == null || role.isEmpty()) {
                    return;
                }
            }
            req.abortWith(Response.status(Response.Status.FORBIDDEN).entity("Sem permissão").build());
        } catch (JwtException e) {
            req.abortWith(Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build());
        }
    }
}
