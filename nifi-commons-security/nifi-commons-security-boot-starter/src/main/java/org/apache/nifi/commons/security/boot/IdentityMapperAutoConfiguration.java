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

import org.apache.nifi.commons.security.identity.IdentityMapper;
import org.apache.nifi.commons.security.identity.DefaultIdentityMapper;
import org.apache.nifi.commons.security.identity.IdentityMapperProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class IdentityMapperAutoConfiguration {

    static final String PROPERTIES_PREFIX = "security.user.identity-mapper";

    @Bean
    @ConfigurationProperties(PROPERTIES_PREFIX)
    public IdentityMapperProperties identityMapperProperties() {
        return new IdentityMapperProperties();
    }

    @Bean
    @ConditionalOnProperty(prefix = IdentityMapperAutoConfiguration.PROPERTIES_PREFIX, name = "enabled")
    public IdentityMapper identityMapper() {
        return new DefaultIdentityMapper(identityMapperProperties());
    }


    @Configuration
    @ConditionalOnMissingBean(IdentityMapper.class)
    public static class DefaultConfiguration {

        @Bean
        public IdentityMapper noopIdentityMapper() {
            return new IdentityMapper() {
                @Override
                public String mapIdentity(String identity) {
                    return identity;
                }
            };
        }

    }



}
