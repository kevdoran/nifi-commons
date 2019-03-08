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
package org.apache.nifi.commons.security.proxy;

import org.apache.nifi.commons.security.identity.BaseIdentityProviderProperties;

import java.util.Collection;

public class ProxyIdentityProviderProperties extends BaseIdentityProviderProperties {

    private boolean enabled = false;
    private String headerName = "x-webauth-user";
    private Collection<String> ipWhitelist;
    private Collection<String> dnWhitelist;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getHeaderName() {
        return headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public Collection<String> getIpWhitelist() {
        return ipWhitelist;
    }

    public void setIpWhitelist(Collection<String> ipWhitelist) {
        this.ipWhitelist = ipWhitelist;
    }

    public Collection<String> getDnWhitelist() {
        return dnWhitelist;
    }

    public void setDnWhitelist(Collection<String> dnWhitelist) {
        this.dnWhitelist = dnWhitelist;
    }
}
