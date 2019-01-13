package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.x509.SubjectDnX509PrincipalExtractor;
import org.apache.nifi.commons.security.x509.X509CertificateExtractor;
import org.apache.nifi.commons.security.x509.X509IdentityProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

@Configuration
@ConditionalOnProperty(prefix = X509CertificateAutoConfiguration.DEFAULT_PREFIX, name = "enabled")
public class X509CertificateAutoConfiguration {

    static final String DEFAULT_PREFIX = "security.user.x509";

    @Bean
    public X509CertificateExtractor x509CertificateExtractor() {
        return new X509CertificateExtractor();
    }

    @Bean
    public X509PrincipalExtractor x509PrincipalExtractor() {
        return new SubjectDnX509PrincipalExtractor();
    }

    @Bean
    @Order(5)
    public X509IdentityProvider x509IdentityProvider() {
        // TODO need to allow these beans to be overwritten
        return new X509IdentityProvider(x509PrincipalExtractor(), x509CertificateExtractor());
    }

}
