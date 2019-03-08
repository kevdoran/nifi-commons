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

package org.apache.nifi.commons.security.kerberos;

import org.apache.nifi.commons.security.identity.BaseIdentityProviderProperties;

import java.io.File;
import java.time.Duration;

public class KerberosSpnegoProperties extends BaseIdentityProviderProperties {

    private boolean enabled;

    private File krb5File;  // TODO, does File type coercion / conversion work?

    private String principal;

    private File keytabFile;  // TODO, does File type coercion / conversion work?

    private Duration expiration;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public File getKrb5File() {
        return krb5File;
    }

    public void setKrb5File(File krb5File) {
        this.krb5File = krb5File;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public File getKeytabFile() {
        return keytabFile;
    }

    public void setKeytabFile(File keytabFile) {
        this.keytabFile = keytabFile;
    }

    public Duration getExpiration() {
        return expiration;
    }

    public void setExpiration(Duration expiration) {
        this.expiration = expiration;
    }

}
