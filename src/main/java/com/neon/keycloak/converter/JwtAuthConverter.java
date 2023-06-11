package com.neon.keycloak.converter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken>
{
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
        new JwtGrantedAuthoritiesConverter();

    @Value("${security.jwt.auth.converter.principal-attribute}")
    private String principalAttribute;
    @Value("${security.jwt.auth.converter.resource-id}")
    private String resourceId;
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt)
    {
        Set<GrantedAuthority> grantedAuthorities = Stream.concat(
            jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
            extractResourceRoles(jwt).stream()
        ).collect(Collectors.toSet());


        return new JwtAuthenticationToken(jwt, grantedAuthorities, extractPrincipalName(jwt));
    }

    private String extractPrincipalName(Jwt jwt)
    {
        if(jwt.getClaim(principalAttribute) != null)
            return jwt.getClaim(principalAttribute);

        return jwt.getClaim(JwtClaimNames.SUB);
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt)
    {
        if (jwt.getClaim("resource_access") == null)
            return Set.of();
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

        if (resourceAccess.get(resourceId) == null)
            return Set.of();
        Map<String, Object> resource = (Map<String, Object>) resourceAccess.get(resourceId);

        Collection<String> roles = (Collection<String>) resource.get("roles");
        if(roles == null || roles.isEmpty())
            return Set.of();

        return roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .collect(Collectors.toSet());
    }
}
