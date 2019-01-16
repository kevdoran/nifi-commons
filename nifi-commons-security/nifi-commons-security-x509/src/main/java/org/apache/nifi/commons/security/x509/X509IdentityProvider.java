/*
 *
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
 *
 */
package org.apache.nifi.commons.security.x509;

import org.apache.nifi.commons.security.exception.InvalidCredentialsException;
import org.apache.nifi.commons.security.identity.AuthenticationRequest;
import org.apache.nifi.commons.security.identity.AuthenticationResponse;
import org.apache.nifi.commons.security.identity.IdentityProvider;
import org.apache.nifi.commons.security.identity.IdentityProviderUsage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 * Identity provider for extract the authenticating a ServletRequest with a X509Certificate.
 */
public class X509IdentityProvider implements IdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(X509IdentityProvider.class);

    private static final String issuer = X509IdentityProvider.class.getSimpleName();

    private static final long expiration = TimeUnit.MILLISECONDS.convert(12, TimeUnit.HOURS);

    private static final IdentityProviderUsage usage = new IdentityProviderUsage() {
        @Override
        public String getText() {
            return "The client must connect over HTTPS and must provide a client certificate during the TLS handshake. ";
        }

        @Override
        public AuthType getAuthType() {
            return AuthType.OTHER.httpAuthScheme("TLS-client-cert");
        }
    };

    private X509PrincipalExtractor principalExtractor;
    private X509CertificateExtractor certificateExtractor;

    public X509IdentityProvider(X509PrincipalExtractor principalExtractor, X509CertificateExtractor certificateExtractor) {
        this.principalExtractor = principalExtractor;
        this.certificateExtractor = certificateExtractor;
    }

    @Override
    public IdentityProviderUsage getUsageInstructions() {
        return usage;
    }

    /**
     * Extracts certificate-based credentials from an {@link HttpServletRequest}.
     *
     * The resulting {@link AuthenticationRequest} will be populated as:
     *  - username: principal DN from first client cert
     *  - credentials: first client certificate (X509Certificate)
     *  - details: proxied-entities chain (String)
     *
     * @param servletRequest the {@link HttpServletRequest} request that may contain credentials understood by this IdentityProvider
     * @return a populated AuthenticationRequest or null if the credentials could not be found.
     */
    @Override
    public AuthenticationRequest extractCredentials(HttpServletRequest servletRequest) {

        // only support x509 login when running securely
        if (!servletRequest.isSecure()) {
            return null;
        }

        // look for a client certificate
        final X509Certificate[] certificates = certificateExtractor.extractClientCertificate(servletRequest);
        if (certificates == null || certificates.length == 0) {
            return null;
        }

        // extract the principal
        final Object certificatePrincipal = principalExtractor.extractPrincipal(certificates[0]);
        final String principal = certificatePrincipal.toString();

        // extract the proxiedEntitiesChain header value from the servletRequest
        // String proxiedEntitiesChainHeader = servletRequest.getHeader(ProxiedEntitiesUtils.PROXY_ENTITIES_CHAIN);
        // TODO figure out how to make proxied entities generic...
        String proxiedEntitiesChainHeader = null;

        return new AuthenticationRequest(principal, certificates[0], proxiedEntitiesChainHeader);

    }

    /**
     * For a given {@link AuthenticationRequest}, this validates the client certificate and creates a populated {@link AuthenticationResponse}.
     *
     * The {@link AuthenticationRequest} authenticationRequest paramenter is expected to be populated as:
     *  - username: principal DN from first client cert
     *  - credentials: first client certificate (X509Certificate)
     *  - details: proxied-entities chain (String)
     *
     * @param authenticationRequest the request, containing identity claim credentials for the IdentityProvider to authenticate and determine an identity
     */
    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) throws InvalidCredentialsException {

        if (authenticationRequest == null || authenticationRequest.getUsername() == null) {
            return null;
        }

        String principal = authenticationRequest.getUsername();

        try {
            X509Certificate clientCertificate = (X509Certificate)authenticationRequest.getCredentials();
            validateClientCertificate(clientCertificate);
        } catch (CertificateExpiredException cee) {
            final String message = String.format("Client certificate for (%s) is expired.", principal);
            logger.warn(message, cee);
            throw new InvalidCredentialsException(message, cee);
        } catch (CertificateNotYetValidException cnyve) {
            final String message = String.format("Client certificate for (%s) is not yet valid.", principal);
            logger.warn(message, cnyve);
            throw new InvalidCredentialsException(message, cnyve);
        } catch (final Exception e) {
            logger.warn(e.getMessage(), e);
        }

        // build the authentication response
        return new AuthenticationResponse(principal, principal, expiration, issuer);
    }

    private void validateClientCertificate(X509Certificate certificate) throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity();
    }

}
