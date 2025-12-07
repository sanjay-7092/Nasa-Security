package com.nasa.security.filters;

import com.nasa.security.utils.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Value("${nasa-authorization-token")
    private String headerToken;

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain){
        String authorizationToken = request.getHeader(headerToken);
        if(authorizationToken!=null){
            String userName = JWTUtil.extractUserName(authorizationToken);
            if(userName!=null&& SecurityContextHolder.getContext().getAuthentication()==null){

            }
        }
    }
}
