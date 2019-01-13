package org.apache.nifi.commons.examples.springboot;

import org.apache.nifi.commons.security.identity.IdentityAuthenticationProvider;
import org.apache.nifi.commons.security.identity.IdentityFilter;
import org.apache.nifi.commons.security.identity.IdentityMapper;
import org.apache.nifi.commons.security.identity.IdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(SpringSecurityConfig.class);

    // TODO add Anon filter to these to nifi-commons-security

    private IdentityMapper identityMapper;
    private List<IdentityProvider> identityProviders;

    @Autowired
    public SpringSecurityConfig(
            IdentityMapper identityMapper,
            List<IdentityProvider> identityProviders) {
        super(true); // disable defaults
        this.identityMapper = identityMapper;
        this.identityProviders = identityProviders;
    }

    @Override
    public void configure(WebSecurity webSecurity) throws Exception {
        // allow any client to access the endpoint for logging in to generate an access token
        //webSecurity.ignoring().antMatchers( "/access/token/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .rememberMe().disable()
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .exceptionHandling()
                // .authenticationEntryPoint(http401AuthenticationEntryPoint())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        for(IdentityProvider identityProvider : identityProviders) {
            final IdentityFilter identityFilter = new IdentityFilter(identityProvider);
            http.addFilterBefore(identityFilter, AnonymousAuthenticationFilter.class);
        }

        // TODO anonymous filter example
        // http.anonymous().authenticationFilter(anonymousAuthenticationFilter);

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        for(IdentityProvider identityProvider : identityProviders) {
            IdentityAuthenticationProvider identityAuthenticationProvider = new IdentityAuthenticationProvider(identityProvider, identityMapper);
            auth.authenticationProvider(identityAuthenticationProvider);
        }
    }

//    private AuthenticationEntryPoint http401AuthenticationEntryPoint() {
//        // This gets used for both secured and unsecured configurations. It will be called by Spring Security if a request makes it through the filter chain without being authenticated.
//        // For unsecured, this should never be reached because the custom AnonymousAuthenticationFilter should always populate a fully-authenticated anonymous user
//        // For secured, this will cause attempt to access any API endpoint (except those explicitly ignored) without providing credentials to return a 401 Unauthorized challenge
//        return new AuthenticationEntryPoint() {
//            @Override
//            public void commence(HttpServletRequest request,
//                                 HttpServletResponse response,
//                                 AuthenticationException authenticationException)
//                    throws IOException, ServletException {
//
//                final int status;
//
//                // See X509IdentityAuthenticationProvider.buildAuthenticatedToken(...)
//                if (authenticationException instanceof UntrustedProxyException) {
//                    // return a 403 response
//                    status = HttpServletResponse.SC_FORBIDDEN;
//                    logger.info("Identity in proxy chain not trusted to act as a proxy: {} Returning 403 response.", authenticationException.toString());
//
//                } else {
//                    // return a 401 response
//                    status = HttpServletResponse.SC_UNAUTHORIZED;
//                    logger.info("Client could not be authenticated due to: {} Returning 401 response.", authenticationException.toString());
//                }
//
//                logger.debug("", authenticationException);
//
//                if (!response.isCommitted()) {
//                    response.setStatus(status);
//                    response.setContentType("text/plain");
//                    response.getWriter().println(String.format("%s Contact the system administrator.", authenticationException.getLocalizedMessage()));
//                }
//            }
//        };
//    }

}
