/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.nifi.commons.security.ldap;

import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.commons.security.exception.IdentityAccessException;
import org.apache.nifi.commons.security.exception.InvalidCredentialsException;
import org.apache.nifi.commons.security.identity.AuthenticationRequest;
import org.apache.nifi.commons.security.identity.AuthenticationResponse;
import org.apache.nifi.commons.security.identity.BasicAuthIdentityProvider;
import org.apache.nifi.commons.security.identity.IdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.core.support.AbstractTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import javax.naming.Context;
import javax.net.ssl.SSLContext;
import java.util.HashMap;
import java.util.Map;

/**
 * LDAP based implementation of a login identity provider.
 */
public class LdapIdentityProvider extends BasicAuthIdentityProvider implements IdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(LdapIdentityProvider.class);

    private static final String issuer = LdapIdentityProvider.class.getSimpleName();

    private AbstractLdapAuthenticationProvider ldapAuthenticationProvider;
    private long expiration;
    private LdapProperties.IdentityStrategy identityStrategy;

    public LdapIdentityProvider(LdapProperties ldapProperties) {
        expiration = ldapProperties.getExpiration().toMillis();
        identityStrategy = ldapProperties.getIdentityStrategy();
        this.ldapAuthenticationProvider = ldapAuthenticationProvider(ldapProperties);
    }

    private LdapAuthenticationProvider ldapAuthenticationProvider(LdapProperties ldapProperties) {
        try {
            final LdapContextSource context = new LdapContextSource();

            context.setUrls((String[])ldapProperties.getUrls().toArray());

            // this needs to be the lowercase version while the value is configured with the enum constant
            context.setReferral(ldapProperties.getReferralStrategy().toString().toLowerCase());

            final Map<String, Object> baseEnvironment = new HashMap<>();
            // TODO, reimplement this
            // connect/read time out
            //setTimeout(configurationContext, baseEnvironment, "Connect Timeout", "com.sun.jndi.ldap.connect.timeout");
            //setTimeout(configurationContext, baseEnvironment, "Read Timeout", "com.sun.jndi.ldap.read.timeout");

            final LdapProperties.LdapAuthenticationStrategy authenticationStrategy = ldapProperties.getAuthenticationStrategy();

            if (LdapProperties.LdapAuthenticationStrategy.ANONYMOUS.equals(authenticationStrategy)) {
                context.setAnonymousReadOnly(true);
            } else {
                context.setUserDn(ldapProperties.getManagerDn());
                context.setPassword(ldapProperties.getManagerPassword());

                switch (authenticationStrategy) {
                    case SIMPLE:
                        context.setAuthenticationStrategy(new SimpleDirContextAuthenticationStrategy());
                        break;
                    case LDAPS:
                        context.setAuthenticationStrategy(new SimpleDirContextAuthenticationStrategy());
                        baseEnvironment.put(Context.SECURITY_PROTOCOL, "ssl"); // indicate a secure connection

                        // get the configured ssl context
                        final SSLContext ldapsSslContext = getConfiguredSslContext(); // TODO
                        if (ldapsSslContext != null) {
                            // initialize the ldaps socket factory prior to use
                            LdapsSocketFactory.initialize(ldapsSslContext.getSocketFactory());
                            baseEnvironment.put("java.naming.ldap.factory.socket", LdapsSocketFactory.class.getName());
                        }
                        break;
                    case START_TLS:
                        final AbstractTlsDirContextAuthenticationStrategy tlsAuthenticationStrategy = new DefaultTlsDirContextAuthenticationStrategy();

                        // TODO
                        // shutdown gracefully
//                    final String rawShutdownGracefully = configurationContext.getProperty("TLS - Shutdown Gracefully");
//                    if (StringUtils.isNotBlank(rawShutdownGracefully)) {
//                        final boolean shutdownGracefully = Boolean.TRUE.toString().equalsIgnoreCase(rawShutdownGracefully);
//                        tlsAuthenticationStrategy.setShutdownTlsGracefully(shutdownGracefully);
//                    }

                        // get the configured ssl context
                        final SSLContext startTlsSslContext = getConfiguredSslContext(); // TODO
                        if (startTlsSslContext != null) {
                            tlsAuthenticationStrategy.setSslSocketFactory(startTlsSslContext.getSocketFactory());
                        }

                        // set the authentication strategy
                        context.setAuthenticationStrategy(tlsAuthenticationStrategy);
                        break;
                }
            }

            // search criteria
            final String userSearchBase = ldapProperties.getUserSearchBase();
            final String userSearchFilter = ldapProperties.getUserSearchFilter();
            final LdapUserSearch userSearch = new FilterBasedLdapUserSearch(userSearchBase, userSearchFilter, context);

            final BindAuthenticator authenticator = new BindAuthenticator(context);
            authenticator.setUserSearch(userSearch);

            // set the base environment is necessary
            if (!baseEnvironment.isEmpty()) {
                context.setBaseEnvironmentProperties(baseEnvironment);
            }

            context.afterPropertiesSet();
            authenticator.afterPropertiesSet();

            return new LdapAuthenticationProvider(authenticator);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialized " + LdapIdentityProvider.class.getSimpleName(), e);
        }

    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) throws InvalidCredentialsException, IdentityAccessException {

        if (authenticationRequest == null || StringUtils.isEmpty(authenticationRequest.getUsername())) {
            logger.debug("Call to authenticate method with null or empty authenticationRequest, returning null without attempting to authenticate");
            return null;
        }

        if (ldapAuthenticationProvider == null) {
            throw new IdentityAccessException("The LDAP authentication provider is not initialized.");
        }

        try {
            final String username = authenticationRequest.getUsername();
            final Object credentials = authenticationRequest.getCredentials();
            final String password = credentials != null && credentials instanceof String ? (String) credentials : null;

            // perform the authentication
            final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, credentials);
            final Authentication authentication = ldapAuthenticationProvider.authenticate(token);
            logger.debug("Created authentication token: {}", token.toString());

            // use dn if configured
            if (LdapProperties.IdentityStrategy.USE_DN.equals(identityStrategy)) {
                // attempt to get the ldap user details to get the DN
                if (authentication.getPrincipal() instanceof LdapUserDetails) {
                    final LdapUserDetails userDetails = (LdapUserDetails) authentication.getPrincipal();
                    return new AuthenticationResponse(userDetails.getDn(), username, expiration, issuer);
                } else {
                    logger.warn(String.format("Unable to determine user DN for %s, using username.", authentication.getName()));
                    return new AuthenticationResponse(authentication.getName(), username, expiration, issuer);
                }
            } else {
                return new AuthenticationResponse(authentication.getName(), username, expiration, issuer);
            }
        } catch (final BadCredentialsException | UsernameNotFoundException | AuthenticationException e) {
            throw new InvalidCredentialsException(e.getMessage(), e);
        } catch (final Exception e) {
            // there appears to be a bug that generates a InternalAuthenticationServiceException wrapped around an AuthenticationException. this
            // shouldn't be the case as they the service exception suggestions that something was wrong with the service. while the authentication
            // exception suggests that username and/or credentials were incorrect. checking the cause seems to address this scenario.
            final Throwable cause = e.getCause();
            if (cause instanceof AuthenticationException) {
                throw new InvalidCredentialsException(e.getMessage(), e);
            }

            logger.error(e.getMessage());
            logger.debug("", e);
            throw new IdentityAccessException("Unable to validate the supplied credentials. Please contact the system administrator.", e);
        }
    }

      // TODO reimplemented ldap timeout
//    private void setTimeout(final IdentityProviderConfigurationContext configurationContext,
//                            final Map<String, Object> baseEnvironment,
//                            final String configurationProperty,
//                            final String environmentKey) {
//
//        final String rawTimeout = configurationContext.getProperty(configurationProperty);
//        if (StringUtils.isNotBlank(rawTimeout)) {
//            try {
//                final Long timeout = FormatUtils.getTimeDuration(rawTimeout, TimeUnit.MILLISECONDS);
//                baseEnvironment.put(environmentKey, timeout.toString());
//            } catch (final IllegalArgumentException iae) {
//                throw new SecurityProviderCreationException(String.format("The %s '%s' is not a valid time duration", configurationProperty, rawTimeout));
//            }
//        }
//    }


    private SSLContext getConfiguredSslContext() {
        // TODO extract this out into a generic implementation
//        final String rawKeystore = configurationContext.getProperty("TLS - Keystore");
//        final String rawKeystorePassword = configurationContext.getProperty("TLS - Keystore Password");
//        final String rawKeystoreType = configurationContext.getProperty("TLS - Keystore Type");
//        final String rawTruststore = configurationContext.getProperty("TLS - Truststore");
//        final String rawTruststorePassword = configurationContext.getProperty("TLS - Truststore Password");
//        final String rawTruststoreType = configurationContext.getProperty("TLS - Truststore Type");
//        final String rawClientAuth = configurationContext.getProperty("TLS - Client Auth");
//        final String rawProtocol = configurationContext.getProperty("TLS - Protocol");
//
//        // create the ssl context
//        final SSLContext sslContext;
//        try {
//            if (StringUtils.isBlank(rawKeystore) && StringUtils.isBlank(rawTruststore)) {
//                sslContext = null;
//            } else {
//                // ensure the protocol is specified
//                if (StringUtils.isBlank(rawProtocol)) {
//                    throw new SecurityProviderCreationException("TLS - Protocol must be specified.");
//                }
//
//                if (StringUtils.isBlank(rawKeystore)) {
//                    sslContext = SslContextFactory.createTrustSslContext(rawTruststore, rawTruststorePassword.toCharArray(), rawTruststoreType, rawProtocol);
//                } else if (StringUtils.isBlank(rawTruststore)) {
//                    sslContext = SslContextFactory.createSslContext(rawKeystore, rawKeystorePassword.toCharArray(), rawKeystoreType, rawProtocol);
//                } else {
//                    // determine the client auth if specified
//                    final ClientAuth clientAuth;
//                    if (StringUtils.isBlank(rawClientAuth)) {
//                        clientAuth = ClientAuth.NONE;
//                    } else {
//                        try {
//                            clientAuth = ClientAuth.valueOf(rawClientAuth);
//                        } catch (final IllegalArgumentException iae) {
//                            throw new SecurityProviderCreationException(String.format("Unrecognized client auth '%s'. Possible values are [%s]",
//                                    rawClientAuth, StringUtils.join(ClientAuth.values(), ", ")));
//                        }
//                    }
//
//                    sslContext = SslContextFactory.createSslContext(rawKeystore, rawKeystorePassword.toCharArray(), rawKeystoreType,
//                            rawTruststore, rawTruststorePassword.toCharArray(), rawTruststoreType, clientAuth, rawProtocol);
//                }
//            }
//        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException | IOException e) {
//            throw new SecurityProviderCreationException(e.getMessage(), e);
//        }
//
//        return sslContext;
        return null;
    }

}
