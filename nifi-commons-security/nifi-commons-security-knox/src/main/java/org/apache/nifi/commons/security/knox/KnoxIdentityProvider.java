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
package org.apache.nifi.commons.security.knox;

import com.nimbusds.jose.JOSEException;
import org.apache.nifi.commons.security.exception.IdentityAccessException;
import org.apache.nifi.commons.security.exception.InvalidCredentialsException;
import org.apache.nifi.commons.security.identity.AuthenticationRequest;
import org.apache.nifi.commons.security.identity.AuthenticationResponse;
import org.apache.nifi.commons.security.identity.IdentityProvider;
import org.apache.nifi.commons.security.identity.IdentityProviderUsage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

public class KnoxIdentityProvider implements IdentityProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(KnoxIdentityProvider.class);

    private static final String ISSUER = KnoxIdentityProvider.class.getSimpleName();

    private static final long EXPIRATION = TimeUnit.MILLISECONDS.convert(12, TimeUnit.HOURS);

    private static final IdentityProviderUsage USAGE = new IdentityProviderUsage() {
        @Override
        public String getText() {
            return "The user credentials must be passed in a cookie with the value being a JWT that will be " +
                    "verified by this identity provider. The name of the cookie is configurable.";
        }

        @Override
        public AuthType getAuthType() {
            return AuthType.OTHER.httpAuthScheme("Apache-Knox-SSO");
        }
    };

    private final KnoxService knoxService;

    @Autowired
    public KnoxIdentityProvider(final KnoxService knoxService) {
        this.knoxService = knoxService;
    }

    @Override
    public IdentityProviderUsage getUsageInstructions() {
        return USAGE;
    }

    @Override
    public AuthenticationRequest extractCredentials(final HttpServletRequest request) {
        // only support knox login when running securely
        if (!request.isSecure()) {
            return null;
        }

        // ensure knox sso support is enabled
        if (!knoxService.isKnoxEnabled()) {
            return null;
        }

        // get the principal out of the user token
        final String knoxJwt = getJwtFromCookie(request, knoxService.getKnoxCookieName());

        // normally in NiFi/NiFi-Registry we would return null here to continue trying other forms of authentication,
        // but in this case, if knox is enabled we want to throw an exception so we'll be re-directed to the Knox login
        if (knoxJwt == null) {
            throw new KnoxAuthenticationException("Knox JWT was not found in the request", knoxService.getKnoxUrl());
        } else {
            // otherwise create the authentication request token
            return new AuthenticationRequest(null, knoxJwt, request.getRemoteAddr());
        }
    }

    private String getJwtFromCookie(final HttpServletRequest request, final String cookieName) {
        String jwt = null;

        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }

        return jwt;
    }

    @Override
    public AuthenticationResponse authenticate(final AuthenticationRequest authenticationRequest)
            throws InvalidCredentialsException, IdentityAccessException {
        if (authenticationRequest == null) {
            LOGGER.info("Cannot authenticate null authenticationRequest, returning null.");
            return null;
        }

        final Object credentials = authenticationRequest.getCredentials();
        if (credentials == null) {
            throw new KnoxAuthenticationException("Knox JWT not found in authenticationRequest credentials", knoxService.getKnoxUrl());
        }

        final String jwtAuthToken = credentials instanceof String ? (String) credentials : null;
        try {
            final String jwtPrincipal = knoxService.getAuthenticationFromToken(jwtAuthToken);
            return new AuthenticationResponse(jwtPrincipal, jwtPrincipal, EXPIRATION, ISSUER);
        } catch (ParseException | JOSEException e) {
            throw new KnoxAuthenticationException(e.getMessage(), e, knoxService.getKnoxUrl());
        }
    }
}
