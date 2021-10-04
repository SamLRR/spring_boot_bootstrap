package web.config.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException, ServletException {
        if (isAdmin(authentication)) {
            httpServletResponse.sendRedirect("/admin");
        } else if (isUser(authentication)) {
            httpServletResponse.sendRedirect("/user");
        } else {
            httpServletResponse.sendRedirect("/login?logout");
        }
    }

    private boolean isAdmin(Authentication authentication) {
        return authentication != null & authentication.getAuthorities()
                .stream().anyMatch(authority -> authority.getAuthority().equals("ADMIN"));
    }

    private boolean isUser(Authentication authentication) {
        return authentication != null & authentication.getAuthorities()
                .stream().anyMatch(authority -> authority.getAuthority().equals("USER"));
    }
}