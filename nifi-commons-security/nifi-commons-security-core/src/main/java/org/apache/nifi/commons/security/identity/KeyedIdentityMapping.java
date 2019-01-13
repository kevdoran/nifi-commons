/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.commons.security.identity;

import java.util.regex.Pattern;

class KeyedIdentityMapping extends IdentityMapping implements Comparable<KeyedIdentityMapping> {

    private final String key;

    KeyedIdentityMapping(String key, IdentityMapping identityMapping) {
        this(key, identityMapping.getPattern(), identityMapping.getReplacementValue());
    }

    KeyedIdentityMapping(String key, Pattern pattern, String replacementValue) {
        super(key, pattern, replacementValue);
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    @Override
    public int compareTo(KeyedIdentityMapping o) {
        return this.key.compareTo(o.key);
    }
}
