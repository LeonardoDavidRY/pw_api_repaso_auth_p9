package uce.edu.web.api.auth.interfaces;

import java.time.Instant;
import java.util.Set;

import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import uce.edu.web.api.auth.application.AuthService;
import uce.edu.web.api.auth.domain.Usuario;

@Path("/auth")
public class AuthResource {

    @Inject
    AuthService authService;

    @GET
    @Path("/token")
    @Produces(MediaType.APPLICATION_JSON) 
    public Response token(
            @QueryParam("user") String user,
            @QueryParam("password") String password) {

        // Validar credenciales contra la base de datos
        Usuario usuario = authService.validarCredenciales(user, password);
        
        if (usuario == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorResponse("Credenciales inválidas"))
                    .build();
        }
        
        String role = usuario.getRol();

        String issuer = "repaso-auth";
        long ttl = 3600;

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttl);

        String jwt = Jwt.issuer(issuer)
                .subject(user)
                .groups(Set.of(role)) // roles: user / admin
                .issuedAt(now)
                .expiresAt(exp)
                .sign();

        return Response.ok(new TokenResponse(jwt, exp.getEpochSecond(), role)).build();
    }

    public static class ErrorResponse {
        public String error;

        public ErrorResponse() {
        }

        public ErrorResponse(String error) {
            this.error = error;
        }
    }

    public static class TokenResponse {
        public String accessToken;
        public long expiresAt;
        public String role;

        public TokenResponse() {
        }

        public TokenResponse(String accessToken, long expiresAt, String role) {
            this.accessToken = accessToken;
            this.expiresAt = expiresAt;
            this.role = role;
        }
    }

}
