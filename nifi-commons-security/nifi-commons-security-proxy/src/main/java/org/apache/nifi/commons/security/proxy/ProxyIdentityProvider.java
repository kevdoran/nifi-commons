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
package org.apache.nifi.commons.security.proxy;

import org.apache.nifi.commons.security.exception.IdentityAccessException;
import org.apache.nifi.commons.security.exception.InvalidCredentialsException;
import org.apache.nifi.commons.security.identity.AuthenticationRequest;
import org.apache.nifi.commons.security.identity.AuthenticationResponse;
import org.apache.nifi.commons.security.identity.IdentityProvider;
import org.apache.nifi.commons.security.identity.IdentityProviderUsage;
import org.apache.nifi.commons.security.util.X509CertificateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

public class ProxyIdentityProvider implements IdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(ProxyIdentityProvider.class);

    private static final String ISSUER = ProxyIdentityProvider.class.getSimpleName();
    private static final long EXPIRATION = TimeUnit.MILLISECONDS.convert(12, TimeUnit.HOURS);
    private static final String DEFAULT_HEADER_NAME = "x-webauth-user";

    private static final IdentityProviderUsage USAGE = new IdentityProviderUsage() {
        @Override
        public String getText() {
            return "The user identity must be passed in a header set by an authenticating proxy. " +
                    "The extracted header fields can be customized via the application properties.";
        }

        @Override
        public AuthType getAuthType() {
            return AuthType.UNKNOWN;
        }
    };

    private final ProxyIdentityProviderProperties properties;
    private X509PrincipalExtractor principalExtractor;

    public ProxyIdentityProvider(ProxyIdentityProviderProperties properties, X509PrincipalExtractor x509PrincipalExtractor) {
        this.principalExtractor = x509PrincipalExtractor;
        this.properties = properties;
        checkForInsecureConfig();
    }

    @Override
    public IdentityProviderUsage getUsageInstructions() {
        return USAGE;
    }

    @Override
    public AuthenticationRequest extractCredentials(HttpServletRequest request) {

        // check if the proxy identity provider is enabled
        if (!properties.isEnabled() || request == null) {
            return null;
        }

        // get the principal out of the user token
        final String headerName = properties.getHeaderName() != null ? properties.getHeaderName(): DEFAULT_HEADER_NAME;
        final String userIdentity = request.getHeader(headerName);

        if (userIdentity == null) {
            return null;
        }

        final String clientIp = request.getRemoteAddr();
        final X509Certificate clientCertificate = X509CertificateUtil.extractClientCertificate(request);
        final ProxyAuthenticationRequest.ProxyCredentials credentials = new ProxyAuthenticationRequest.ProxyCredentials(clientIp, clientCertificate);

        return new ProxyAuthenticationRequest(userIdentity, credentials);
    }

    @Override
    public boolean supports(Class<? extends AuthenticationRequest> authenticationRequestClazz) {
        return ProxyAuthenticationRequest.class.isAssignableFrom(authenticationRequestClazz);
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) throws InvalidCredentialsException, IdentityAccessException {

        if (authenticationRequest == null || !(authenticationRequest instanceof ProxyAuthenticationRequest)) {
            return null;
        }
        final ProxyAuthenticationRequest proxyAuthenticationRequest = (ProxyAuthenticationRequest) authenticationRequest;

        final String identity = authenticationRequest.getUsername();
        if (identity == null) {
            return null;
        }

        // Validate client IP against whitelist (if configured)
        Collection<String> ipWhitelist = properties.getIpWhitelist();
        if (ipWhitelist != null && !ipWhitelist.isEmpty()) {
            final String clientIp = proxyAuthenticationRequest.getCredentials().getClientIp();
            if (clientIp == null || !ipWhitelist.contains(clientIp)) {
                final String message = String.format("Proxy SSO identity was provided (%s), but client IP address (%s) is not in trusted whitelist.", identity, clientIp);
                logger.warn(message);
                throw new InvalidCredentialsException(message);
            }
            logger.debug("Client IP address ({}) is a trusted proxy", clientIp);
        }

        // Validate client cert DN against whitelist (if configured)
        Collection<String> dnWhitelist = properties.getDnWhitelist();
        if (dnWhitelist != null && !dnWhitelist.isEmpty()) {
            final X509Certificate clientCert = proxyAuthenticationRequest.getCredentials().getClientCertificate();
            X509CertificateUtil.validateClientCertificateOrThrow(clientCert);
            final String clientCertDN = principalExtractor.extractPrincipal(clientCert).toString();
            if (clientCertDN == null || !dnWhitelist.contains(clientCertDN)) {
                final String message = String.format("Proxy SSO identity was provided (%s), but client certificate DN (%s) is not in trusted whitelist.", identity, clientCertDN);
                logger.warn(message);
                throw new InvalidCredentialsException(message);
            }
            logger.debug("Client DN ({}) is a trusted proxy.", clientCertDN);
        }

        logger.debug("Using user identity '{}' passed by proxy.", identity);

        final AuthenticationResponse authenticationResponse = new AuthenticationResponse(identity, identity, EXPIRATION, ISSUER);
        return authenticationResponse;
    }

    public void setPrincipalExtractor(X509PrincipalExtractor principalExtractor) {
        this.principalExtractor = principalExtractor;
    }

    private void checkForInsecureConfig() {
        boolean proxyWhitelistEnabled =
                (properties.getIpWhitelist() != null
                        && !properties.getIpWhitelist().isEmpty())
                || (properties.getDnWhitelist() != null
                        && !properties.getDnWhitelist().isEmpty());

        if (this.properties.isEnabled() && !proxyWhitelistEnabled) {
            logger.warn("External Proxy Authentication is enabled without DN whitelist or IP whitelist settings. " +
                    "The service may be vulnerable to user impersonation if it is bound to a network other than localhost. " +
                    "Please verify your configuration.");
        }
    }
}
