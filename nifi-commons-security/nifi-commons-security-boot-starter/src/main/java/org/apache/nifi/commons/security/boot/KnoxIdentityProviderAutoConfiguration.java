package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.identity.IdentityFilter;
import org.apache.nifi.commons.security.knox.KnoxIdentityProvider;
import org.apache.nifi.commons.security.knox.KnoxProperties;
import org.apache.nifi.commons.security.knox.KnoxService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(prefix = KnoxIdentityProviderAutoConfiguration.DEFAULT_PREFIX, name = "enabled")
public class KnoxIdentityProviderAutoConfiguration {

    static final String DEFAULT_PREFIX = "security.user.knox";

    @Bean
    @ConfigurationProperties(prefix = DEFAULT_PREFIX)
    public KnoxProperties knoxProperties() {
        return new KnoxProperties();
    }

    @Bean
    public KnoxService knoxService() {
        return new KnoxService(knoxProperties());
    }

    @Bean
    public KnoxIdentityProvider knoxIdentityProvider() {
        return new KnoxIdentityProvider(knoxService());
    }

    @Bean
    public IdentityFilter knoxIdentityFilter() {
        return new IdentityFilter(knoxIdentityProvider());
    }

}
