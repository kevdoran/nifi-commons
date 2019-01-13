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

package org.apache.nifi.commons.security.ldap;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.time.Duration;
import java.util.Set;

public class LdapProperties {

//    <!--
//    Identity Provider for users logging in with username/password against an LDAP server.
//
//        'Authentication Strategy' - How the connection to the LDAP server is authenticated. Possible
//    values are ANONYMOUS, SIMPLE, LDAPS, or START_TLS.
//
//            'Manager DN' - The DN of the manager that is used to bind to the LDAP server to search for users.
//            'Manager Password' - The password of the manager that is used to bind to the LDAP server to
//    search for users.
//
//
//            'Referral Strategy' - Strategy for handling referrals. Possible values are FOLLOW, IGNORE, THROW.
//            'Connect Timeout' - Duration of connect timeout. (i.e. 10 secs).
//            'Read Timeout' - Duration of read timeout. (i.e. 10 secs).
//
//            'Url' - Space-separated list of URLs of the LDAP servers (i.e. ldap://<hostname>:<port>).
//            'User Search Base' - Base DN for searching for users (i.e. CN=Users,DC=example,DC=com).
//            'User Search Filter' - Filter for searching for users against the 'User Search Base'.
//            (i.e. sAMAccountName={0}). The user specified name is inserted into '{0}'.
//
//            'Identity Strategy' - Strategy to identify users. Possible values are USE_DN and USE_USERNAME.
//    The default functionality if this property is missing is USE_DN in order to retain
//    backward compatibility. USE_DN will use the full DN of the user entry if possible.
//    USE_USERNAME will use the username the user logged in with.
//            'Authentication Expiration' - The duration of how long the user authentication is valid
//            for. If the user never logs out, they will be required to log back in following
//            this duration.
//    -->

    private boolean enabled;

    @NotEmpty
    private Set<String> urls;

    private Duration expiration;

    private ReferralStrategy referralStrategy = ReferralStrategy.FOLLOW;

    private LdapAuthenticationStrategy authenticationStrategy = LdapAuthenticationStrategy.ANONYMOUS;

    private String managerDn;
    private String managerPassword;

    @NotBlank
    private String userSearchBase;
    @NotBlank
    private String userSearchFilter;

    private IdentityStrategy identityStrategy = IdentityStrategy.USE_DN;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getUrls() {
        return urls;
    }

    public void setUrls(Set<String> urls) {
        this.urls = urls;
    }

    public Duration getExpiration() {
        return expiration;
    }

    public void setExpiration(Duration expiration) {
        this.expiration = expiration;
    }

    public ReferralStrategy getReferralStrategy() {
        return referralStrategy;
    }

    public void setReferralStrategy(ReferralStrategy referralStrategy) {
        this.referralStrategy = referralStrategy;
    }

    public LdapAuthenticationStrategy getAuthenticationStrategy() {
        return authenticationStrategy;
    }

    public void setAuthenticationStrategy(LdapAuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }

    public String getManagerDn() {
        return managerDn;
    }

    public void setManagerDn(String managerDn) {
        this.managerDn = managerDn;
    }

    public String getManagerPassword() {
        return managerPassword;
    }

    public void setManagerPassword(String managerPassword) {
        this.managerPassword = managerPassword;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public void setUserSearchFilter(String userSearchFilter) {
        this.userSearchFilter = userSearchFilter;
    }

    public IdentityStrategy getIdentityStrategy() {
        return identityStrategy;
    }

    public void setIdentityStrategy(IdentityStrategy identityStrategy) {
        this.identityStrategy = identityStrategy;
    }

    public enum LdapAuthenticationStrategy {
        ANONYMOUS,
        SIMPLE,
        LDAPS,
        START_TLS,
    }

    public static enum referralStrategy {
        FOLLOW,
        IGNORE,
        THROW,
    }

    public static enum IdentityStrategy {
        USE_DN,
        USE_USERNAME,
    }

    public static class SecureProperties {

        private boolean enabled;

        private Type type;
        private ClientAuth clientAuth;
        private String[] enabledProtocols;
        private String keyAlias;
        private String keyPassword;
        private String keyStore;
        private String keyStorePassword;
        private String keyStoreType;
        private String keyStoreProvider;
        private String trustStore;
        private String trustStorePassword;
        private String trustStoreType;
        private String trustStoreProvider;
        private String protocol = "TLS";

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public ClientAuth getClientAuth() {
            return this.clientAuth;
        }

        public void setClientAuth(ClientAuth clientAuth) {
            this.clientAuth = clientAuth;
        }

        public String[] getEnabledProtocols() {
            return this.enabledProtocols;
        }

        public void setEnabledProtocols(String[] enabledProtocols) {
            this.enabledProtocols = enabledProtocols;
        }

        public String getKeyAlias() {
            return this.keyAlias;
        }

        public void setKeyAlias(String keyAlias) {
            this.keyAlias = keyAlias;
        }

        public String getKeyPassword() {
            return this.keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }

        public String getKeyStore() {
            return this.keyStore;
        }

        public void setKeyStore(String keyStore) {
            this.keyStore = keyStore;
        }

        public String getKeyStorePassword() {
            return this.keyStorePassword;
        }

        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        public String getKeyStoreType() {
            return this.keyStoreType;
        }

        public void setKeyStoreType(String keyStoreType) {
            this.keyStoreType = keyStoreType;
        }

        public String getKeyStoreProvider() {
            return this.keyStoreProvider;
        }

        public void setKeyStoreProvider(String keyStoreProvider) {
            this.keyStoreProvider = keyStoreProvider;
        }

        public String getTrustStore() {
            return this.trustStore;
        }

        public void setTrustStore(String trustStore) {
            this.trustStore = trustStore;
        }

        public String getTrustStorePassword() {
            return this.trustStorePassword;
        }

        public void setTrustStorePassword(String trustStorePassword) {
            this.trustStorePassword = trustStorePassword;
        }

        public String getTrustStoreType() {
            return this.trustStoreType;
        }

        public void setTrustStoreType(String trustStoreType) {
            this.trustStoreType = trustStoreType;
        }

        public String getTrustStoreProvider() {
            return this.trustStoreProvider;
        }

        public void setTrustStoreProvider(String trustStoreProvider) {
            this.trustStoreProvider = trustStoreProvider;
        }

        public String getProtocol() {
            return this.protocol;
        }

        public void setProtocol(String protocol) {
            this.protocol = protocol;
        }

        public static enum ClientAuth {
            NONE,
            WANT,
            NEED;
        }

        public static enum Type {
            LDAPS,
            START_TLS;
            // AUTO ? // TODO look into supporting automatic LDAPS/TLS protocol detection
        }

    }

}
