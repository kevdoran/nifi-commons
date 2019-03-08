package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.identity.IdentityAuthenticationProvider;
import org.apache.nifi.commons.security.identity.IdentityFilter;
import org.apache.nifi.commons.security.identity.IdentityMapper;
import org.apache.nifi.commons.security.x509.SubjectDnX509PrincipalExtractor;
import org.apache.nifi.commons.security.x509.X509CertificateExtractor;
import org.apache.nifi.commons.security.x509.X509IdentityProvider;
import org.apache.nifi.commons.security.x509.X509IdentityProviderProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import java.util.Optional;

@Configuration
@ConditionalOnProperty(prefix = X509CertificateAutoConfiguration.DEFAULT_PREFIX, name = "enabled")
public class X509CertificateAutoConfiguration {

    static final String DEFAULT_PREFIX = "security.user.certificate";

    private final IdentityMapper identityMapper;

    @Autowired
    public X509CertificateAutoConfiguration(Optional<IdentityMapper> identityMapper) {
        this.identityMapper = identityMapper.orElse(null);
    }

    @Bean
    @ConfigurationProperties(DEFAULT_PREFIX)
    public X509IdentityProviderProperties x509IdentityProviderProperties() {
        return new X509IdentityProviderProperties();
    }

    @Bean
    public X509CertificateExtractor x509CertificateExtractor() {
        return new X509CertificateExtractor();
    }

    @Bean
    public X509PrincipalExtractor x509PrincipalExtractor() {
        return new SubjectDnX509PrincipalExtractor();
    }

    @Bean
    public X509IdentityProvider x509IdentityProvider() {
        // TODO need to allow these beans to be overwritten
        return new X509IdentityProvider(x509PrincipalExtractor(), x509CertificateExtractor());
    }

    @Bean
    public IdentityFilter x509IdentityFilter() {
        return new IdentityFilter(x509IdentityProvider());
    }

    @Bean
    IdentityAuthenticationProvider x509IdentityAuthenticationProvider() {
        return new IdentityAuthenticationProvider(x509IdentityProvider(), identityMapper);
    }

}
