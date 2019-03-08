package org.apache.nifi.commons.security.x509;

import org.apache.nifi.commons.security.identity.BaseIdentityProviderProperties;

public class X509IdentityProviderProperties extends BaseIdentityProviderProperties {

    private boolean enabled;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
