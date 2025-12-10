package com.nasa.security.filters;

import com.nasa.security.models.UserToken;
import com.nasa.security.service.UserTokenService;
import com.nasa.security.utils.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Value("${nasa-authorization-token")
    private String headerToken;

    private final UserTokenService userTokenService;

    protected JwtTokenFilter(UserTokenService userTokenService){
        this.userTokenService=userTokenService;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException,IOException {
        String authorizationToken = request.getHeader(headerToken);
        if(authorizationToken!=null){
            String userName = JWTUtil.extractUserName(authorizationToken);
            if(userName!=null&& SecurityContextHolder.getContext().getAuthentication()==null){
                UserToken userToken = userTokenService.getByUserName(userName);
                if(JWTUtil.validateToken(authorizationToken,userToken)){
                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userToken,null,null);
                    token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(token);
                }
              filterChain.doFilter(request,response);
            }
        }
    }
}
