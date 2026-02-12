package uce.edu.web.api.auth.application;

import jakarta.enterprise.context.ApplicationScoped;
import uce.edu.web.api.auth.domain.Usuario;

@ApplicationScoped
public class AuthService {

    /**
     * Valida las credenciales del usuario contra la base de datos
     * @param username nombre de usuario
     * @param password contraseña en texto plano
     * @return Usuario si las credenciales son válidas, null en caso contrario
     */
    public Usuario validarCredenciales(String username, String password) {
        if (username == null || password == null) {
            return null;
        }

        // Buscar usuario por username
        Usuario usuario = Usuario.find("username", username).firstResult();
        
        if (usuario == null) {
            return null;
        }

        // Comparar contraseña (si está hasheada con BCrypt, usar BcryptUtil.matches)
        // Por ahora comparación directa si están en texto plano
        if (password.equals(usuario.getContrasenia())) {
            return usuario;
        }

        return null;
    }

    /**
     * Valida credenciales usando BCrypt (si las contraseñas están hasheadas)
     * Descomenta este método si usas BCrypt
     */
    /*
    public Usuario validarCredencialesBcrypt(String username, String password) {
        if (username == null || password == null) {
            return null;
        }

        Usuario usuario = Usuario.find("username", username).firstResult();
        
        if (usuario == null) {
            return null;
        }

        // Verificar password hasheado con BCrypt
        if (io.quarkus.elytron.security.common.BcryptUtil.matches(password, usuario.getContrasenia())) {
            return usuario;
        }

        return null;
    }
    */
}
