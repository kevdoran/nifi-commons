package org.apache.nifi.commons.security.boot;

import org.apache.nifi.commons.security.identity.IdentityFilter;
import org.apache.nifi.commons.security.kerberos.KerberosSpnegoIdentityProvider;
import org.apache.nifi.commons.security.kerberos.KerberosSpnegoProperties;
import org.apache.nifi.commons.security.kerberos.KerberosUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;
import org.springframework.security.kerberos.authentication.sun.GlobalSunJaasKerberosConfig;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;

import java.io.File;
import java.util.Optional;

@Configuration
@ConditionalOnProperty(prefix = KerberosSpnegoAutoConfiguration.DEFAULT_PREFIX, name = "enabled")
public class KerberosSpnegoAutoConfiguration {

    static final String DEFAULT_PREFIX = "security.user.kerberos";

    private KerberosTicketValidator kerberosTicketValidator;
    private KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider;
    private KerberosSpnegoIdentityProvider kerberosSpnegoIdentityProvider;

    @Autowired
    public KerberosSpnegoAutoConfiguration(Optional<KerberosTicketValidator> kerberosTicketValidator) {
        this.kerberosTicketValidator = kerberosTicketValidator.orElse(kerberosTicketValidator());
    }

    @Bean
    @ConfigurationProperties(prefix = DEFAULT_PREFIX)
    public KerberosSpnegoProperties kerberosSpnegoProperties() {
        return new KerberosSpnegoProperties();
    }

    // TODO, is this even needed or is there a spring security bean we can use? one with config props?
    @Bean
    public KerberosTicketValidator kerberosTicketValidator() {
        final KerberosSpnegoProperties properties = kerberosSpnegoProperties();
        if (kerberosTicketValidator == null && properties.isEnabled()) {

            try {
                // Configure SunJaasKerberos (global)
                final File krb5ConfigFile = properties.getKrb5File();  // TODO, resolve type mis-match ?
                if (krb5ConfigFile != null) {
                    final GlobalSunJaasKerberosConfig krb5Config = new GlobalSunJaasKerberosConfig();
                    krb5Config.setKrbConfLocation(krb5ConfigFile.getAbsolutePath());
                    krb5Config.afterPropertiesSet();
                }

                // Create ticket validator to inject into KerberosServiceAuthenticationProvider
                SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
                ticketValidator.setServicePrincipal(properties.getPrincipal());
                ticketValidator.setKeyTabLocation(new FileSystemResource(properties.getKeytabFile()));
                ticketValidator.afterPropertiesSet();

                kerberosTicketValidator = ticketValidator;
            } catch (Exception e) {
                throw new RuntimeException("Could not initialize " + KerberosSpnegoIdentityProvider.class.getSimpleName(), e);
            }

        }

        return kerberosTicketValidator;
    }

    // TODO, is this even needed or is there a spring security bean we can use? one with config props?
    @Bean
    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
        final KerberosSpnegoProperties properties = kerberosSpnegoProperties();
        if (kerberosServiceAuthenticationProvider == null && properties.isEnabled()) {
            try {
                KerberosServiceAuthenticationProvider ksap = new KerberosServiceAuthenticationProvider();
                ksap.setTicketValidator(kerberosTicketValidator);
                ksap.setUserDetailsService(new KerberosUserDetailsService());
                ksap.afterPropertiesSet();
                kerberosServiceAuthenticationProvider = ksap;
            } catch (Exception e) {
                throw new RuntimeException("Could not initialize " + KerberosSpnegoIdentityProvider.class.getSimpleName(), e);
            }
        }
        return kerberosServiceAuthenticationProvider;
    }

    @Bean
    public KerberosSpnegoIdentityProvider kerberosSpnegoIdentityProvider() {
        final KerberosSpnegoProperties properties = kerberosSpnegoProperties();
        if (kerberosSpnegoIdentityProvider == null && properties.isEnabled()) {
            kerberosSpnegoIdentityProvider = new KerberosSpnegoIdentityProvider(
                    kerberosServiceAuthenticationProvider(),
                    properties);
        }
        return kerberosSpnegoIdentityProvider;
    }

    @Bean
    public IdentityFilter kerberosSpnegoIdentityFilter() {
        return new IdentityFilter(kerberosSpnegoIdentityProvider());
    }

}
