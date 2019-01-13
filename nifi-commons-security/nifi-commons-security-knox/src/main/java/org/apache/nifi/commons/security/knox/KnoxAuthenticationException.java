package org.apache.nifi.commons.security.knox;/*
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

import org.springframework.security.core.AuthenticationException;

import java.util.Objects;

/**
 * Thrown if the Knox JWT is missing or invalid.
 *
 * Indicates that a re-direct to Knox should be performed, see http401AuthenticationEntryPoint() in C2SecurityConfig.
 */
public class KnoxAuthenticationException extends AuthenticationException {

    private final String knoxUrl;

    public KnoxAuthenticationException(String msg, Throwable t, String knoxUrl) {
        super(msg, t);
        this.knoxUrl = knoxUrl;
        Objects.requireNonNull(this.knoxUrl);
    }

    public KnoxAuthenticationException(String msg, String knoxUrl) {
        super(msg);
        this.knoxUrl = knoxUrl;
        Objects.requireNonNull(this.knoxUrl);
    }

    public String getKnoxUrl() {
        return knoxUrl;
    }

}
