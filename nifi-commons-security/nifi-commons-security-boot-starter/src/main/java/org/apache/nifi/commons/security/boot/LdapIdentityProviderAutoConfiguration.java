package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.identity.IdentityFilter;
import org.apache.nifi.commons.security.ldap.LdapIdentityProvider;
import org.apache.nifi.commons.security.ldap.LdapProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
    public LdapIdentityProvider ldapIdentityProvider() {
        return new LdapIdentityProvider(ldapProperties());
    }

    @Bean
    public IdentityFilter ldapIdentityFilter() {
        return new IdentityFilter(ldapIdentityProvider());
    }

}
