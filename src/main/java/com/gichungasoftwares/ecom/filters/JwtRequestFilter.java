package com.gichungasoftwares.ecom.filters;

import com.gichungasoftwares.ecom.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    //create objects for userDetailsService and JwtUtil
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        //  get the authheader of the request
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        //add a validation to check if auth header is null
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            // get the token from auth header
            token = authHeader.substring(7);
            username = jwtUtil.extractUsernameFromToken(token);
        }

        //check that the username is not null and that the security context holder is null
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // get the user details from the user details service
            UserDetails userDetails = UserDetailsService.loadUserByUsername(username);

            // validate token
            if(jwtUtil.validateToken(token, userDetails)){
                // create the user password authentication token
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null);

                // set details of the request in our authentication token
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // update the security context holder with latest auth token
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
