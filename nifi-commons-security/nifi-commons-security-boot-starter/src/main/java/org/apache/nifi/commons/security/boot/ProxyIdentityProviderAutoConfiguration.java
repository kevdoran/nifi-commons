/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.proxy.ProxyIdentityProvider;
import org.apache.nifi.commons.security.proxy.ProxyIdentityProviderProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import java.util.Optional;

@Configuration
@ConditionalOnProperty(prefix = ProxyIdentityProviderAutoConfiguration.DEFAULT_PREFIX, name = "enabled")
public class ProxyIdentityProviderAutoConfiguration {

    static final String DEFAULT_PREFIX = "security.user.proxy";

    private X509PrincipalExtractor x509PrincipalExtractor;

    @Autowired
    public ProxyIdentityProviderAutoConfiguration(Optional<X509PrincipalExtractor> x509PrincipalExtractor) {
        this.x509PrincipalExtractor = x509PrincipalExtractor.orElse(new SubjectDnX509PrincipalExtractor());
    }

    @Bean
    @ConfigurationProperties(prefix = DEFAULT_PREFIX)
    public ProxyIdentityProviderProperties proxyIdentityProviderProperties() {
        return new ProxyIdentityProviderProperties();
    }

    @Bean
    @Order(1)
    public ProxyIdentityProvider proxyIdentityProvider() {
        return new ProxyIdentityProvider(proxyIdentityProviderProperties(), x509PrincipalExtractor);
    }

}
