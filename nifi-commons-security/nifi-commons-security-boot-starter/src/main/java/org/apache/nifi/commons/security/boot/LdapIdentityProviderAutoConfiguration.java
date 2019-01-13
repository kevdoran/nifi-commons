package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.ldap.LdapIdentityProvider;
import org.apache.nifi.commons.security.ldap.LdapProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

@Configuration
@ConditionalOnProperty(prefix = LdapIdentityProviderAutoConfiguration.DEFAULT_PREFIX, name = "enabled")
public class LdapIdentityProviderAutoConfiguration {

    static final String DEFAULT_PREFIX = "security.user.ldap";

    @Bean
    @ConfigurationProperties(prefix = DEFAULT_PREFIX)
    public LdapProperties ldapProperties() {
        return new LdapProperties();
    }

    @Bean
    @Order(4) // TODO make this user configurable
    public LdapIdentityProvider ldapIdentityProvider() {
        return new LdapIdentityProvider(ldapProperties());
    }

}
