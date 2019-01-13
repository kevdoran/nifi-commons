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
package org.apache.nifi.commons.security.proxy;

import org.apache.nifi.commons.security.identity.AuthenticationRequest;

import java.security.cert.X509Certificate;

public class ProxyAuthenticationRequest extends AuthenticationRequest {

    public ProxyAuthenticationRequest(String username, ProxyCredentials credentials) {
        super(username, credentials, null);
    }

    @Override
    public ProxyCredentials getCredentials() {
        return (ProxyCredentials)super.getCredentials();
    }

    @Override
    public void setCredentials(Object credentials) {
        if (!(credentials instanceof ProxyCredentials)) {
            throw new IllegalArgumentException("Proxy Authentication Request credentials must be instance of " + ProxyCredentials.class.getSimpleName());
        }
        super.setCredentials(credentials);
    }

    public static class ProxyCredentials {
        private String clientIp;
        private X509Certificate clientCertificate;

        public ProxyCredentials() {
        }

        public ProxyCredentials(String clientIp, X509Certificate clientCertificate) {
            this.clientIp = clientIp;
            this.clientCertificate = clientCertificate;
        }

        public String getClientIp() {
            return clientIp;
        }

        public void setClientIp(String clientIp) {
            this.clientIp = clientIp;
        }

        public X509Certificate getClientCertificate() {
            return clientCertificate;
        }

        public void setClientCertificate(X509Certificate clientCertificate) {
            this.clientCertificate = clientCertificate;
        }
    }


}
