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
package org.apache.nifi.commons.security.identity;

import org.apache.nifi.commons.security.UserDetails;
import org.apache.nifi.commons.security.StandardUser;
import org.apache.nifi.commons.security.exception.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;


public class IdentityAuthenticationProvider implements AuthenticationProvider, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(IdentityAuthenticationProvider.class);

    //protected Authorizer authorizer;
    protected final IdentityProvider identityProvider;
    protected final IdentityMapper identityMapper;

    public IdentityAuthenticationProvider(
            //Authorizer authorizer,
            IdentityProvider identityProvider) {
        // this.authorizer = authorizer;
        this(identityProvider, null);
    }

    public IdentityAuthenticationProvider(
            //Authorizer authorizer,
            IdentityProvider identityProvider,
            IdentityMapper identityMapper) {
        // this.authorizer = authorizer;
        this.identityProvider = identityProvider;
        this.identityMapper = identityMapper;
    }

    @Override
    public int getOrder() {
        return identityProvider.getOrder();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // Determine if this AuthenticationProvider's identityProvider should be able to support this AuthenticationRequest
        boolean tokenOriginatedFromThisIdentityProvider = checkTokenOriginatedFromThisIdentityProvider(authentication);

        if (!tokenOriginatedFromThisIdentityProvider) {
            // Returning null indicates to The Spring Security AuthenticationManager that this AuthenticationProvider
            // cannot authenticate this token and another provider should be tried.
            return null;
        }

        AuthenticationRequestToken authenticationRequestToken = ((AuthenticationRequestToken)authentication);
        AuthenticationRequest authenticationRequest = authenticationRequestToken.getAuthenticationRequest();

        try {
            AuthenticationResponse authenticationResponse = identityProvider.authenticate(authenticationRequest);
            if (authenticationResponse == null) {
                return null;
            }
            return buildAuthenticatedToken(authenticationRequestToken, authenticationResponse);
        } catch (InvalidCredentialsException e) {
            throw new BadCredentialsException("Identity Provider authentication failed.", e);
        }

    }

    @Override
    public boolean supports(Class<?> authenticationClazz) {
        // is authenticationClazz a subclass of AuthenticationRequestWrapper?
        return AuthenticationRequestToken.class.isAssignableFrom(authenticationClazz);
    }

    protected AuthenticationSuccessToken buildAuthenticatedToken(
            AuthenticationRequestToken requestToken,
            AuthenticationResponse response) {

        final String mappedIdentity = mapIdentity(response.getIdentity());

        return new AuthenticationSuccessToken(new UserDetails(
                new StandardUser.Builder()
                        .identity(mappedIdentity)
                        //.groups(getUserGroups(mappedIdentity))
                        .clientAddress(requestToken.getClientAddress())
                        .build()));
    }

    protected boolean checkTokenOriginatedFromThisIdentityProvider(Authentication authentication) {
        return (authentication instanceof AuthenticationRequestToken
                && identityProvider.getClass().equals(((AuthenticationRequestToken) authentication).getAuthenticationRequestOrigin()));
    }

    protected String mapIdentity(final String identity) {
        if (identityMapper == null) {
            return identity;
        }
        return identityMapper.mapIdentity(identity);
    }

//    protected Set<String> getUserGroups(final String identity) {
//        return getUserGroups(authorizer, identity);
//    }
//
//    private static Set<String> getUserGroups(final Authorizer authorizer, final String userIdentity) {
//        if (authorizer instanceof ManagedAuthorizer) {
//            final ManagedAuthorizer managedAuthorizer = (ManagedAuthorizer) authorizer;
//            final UserGroupProvider userGroupProvider = managedAuthorizer.getAccessPolicyProvider().getUserGroupProvider();
//            final UserAndGroups userAndGroups = userGroupProvider.getUserAndGroups(userIdentity);
//            final Set<Group> userGroups = userAndGroups.getGroups();
//
//            if (userGroups == null || userGroups.isEmpty()) {
//                return Collections.emptySet();
//            } else {
//                return userAndGroups.getGroups().stream().map(Group::getName).collect(Collectors.toSet());
//            }
//        } else {
//            return null;
//        }
//    }
}
