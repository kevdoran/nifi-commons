/*
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
 */

package org.apache.nifi.commons.security.knox;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

public class KnoxProperties {

    private boolean enabled;

    private String url;

    private Set<String> audiences;

    private String cookieName;

    private String publicKey;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Set<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(Set<String> audiences) {
        this.audiences = audiences;
    }

    public String getCookieName() {
        return cookieName;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public RSAPublicKey getKnoxPublicKey() {
        // get the path to the public key
        final Path knoxPublicKeyPath = Paths.get(publicKey);

        // ensure the file exists
        if (Files.isRegularFile(knoxPublicKeyPath) && Files.exists(knoxPublicKeyPath)) {
            try (final InputStream publicKeyStream = Files.newInputStream(knoxPublicKeyPath)) {
                final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(publicKeyStream);
                return (RSAPublicKey) certificate.getPublicKey();
            } catch (final IOException | CertificateException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        } else {
            throw new RuntimeException(String.format("The specified Knox public key path does not exist '%s'", knoxPublicKeyPath.toString()));
        }
    }
}
