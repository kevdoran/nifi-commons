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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DefaultIdentityMapper implements IdentityMapper {

    private static final Logger logger = LoggerFactory.getLogger(DefaultIdentityMapper.class);
    private static final Pattern BACK_REFERENCE_PATTERN = Pattern.compile("\\$(\\d+)");

    private final List<KeyedIdentityMapperRule> mappings;

    public DefaultIdentityMapper(IdentityMapperProperties properties) {

        // TODO, build mappings
        final Map<String, IdentityMapperRule> propertiesMappings = properties.getRules();
        if (propertiesMappings == null) {
            mappings = new ArrayList<>();
        } else {
            mappings = new ArrayList<>(propertiesMappings.size());
            for (Map.Entry<String, IdentityMapperRule> mapping : propertiesMappings.entrySet()) {
                if (mapping.getKey() != null && mapping.getValue() != null && mapping.getValue().getPattern() != null && mapping.getValue().getReplacement() != null) {
                    mappings.add(new KeyedIdentityMapperRule(mapping.getKey(), mapping.getValue()));
                } else {
                    logger.warn(
                            "Invalid Identity Mapping Configuration. All fields must be present: key={}, pattern={}, value={}",
                            mapping.getKey(),
                            mapping.getValue() != null ? mapping.getValue().getPattern() : null,
                            mapping.getValue() != null ? mapping.getValue().getReplacement() : null);
                }
            }
            Collections.sort(mappings);
            logger.debug("Loaded {} identity mappings", mappings.size());
        }

    }

    @Override
    public String mapIdentity(final String identity) {
        for (KeyedIdentityMapperRule mapping : mappings) {
            Matcher m = mapping.getPattern().matcher(identity);
            if (m.matches()) {
                final String pattern = mapping.getPattern().pattern();
                final String replacementValue = escapeLiteralBackReferences(mapping.getReplacement(), m.groupCount());
                logger.debug("Mapped identity based on '{}' rule, resulting in identity='{}'", mapping.getKey());
                return identity.replaceAll(pattern, replacementValue);
            }
        }

        return identity;
    }

    // If we find a back reference that is not valid, then we will treat it as a literal string. For example, if we have 3 capturing
    // groups and the Replacement Value has the value is "I owe $8 to him", then we want to treat the $8 as a literal "$8", rather
    // than attempting to use it as a back reference.
    private static String escapeLiteralBackReferences(final String unescaped, final int numCapturingGroups) {
        if (numCapturingGroups == 0) {
            return unescaped;
        }

        String value = unescaped;
        final Matcher backRefMatcher = BACK_REFERENCE_PATTERN.matcher(value);
        while (backRefMatcher.find()) {
            final String backRefNum = backRefMatcher.group(1);
            if (backRefNum.startsWith("0")) {
                continue;
            }
            int backRefIndex = Integer.parseInt(backRefNum);

            // if we have a replacement value like $123, and we have less than 123 capturing groups, then
            // we want to truncate the 3 and use capturing group 12; if we have less than 12 capturing groups,
            // then we want to truncate the 2 and use capturing group 1; if we don't have a capturing group then
            // we want to truncate the 1 and get 0.
            while (backRefIndex > numCapturingGroups && backRefIndex >= 10) {
                backRefIndex /= 10;
            }

            if (backRefIndex > numCapturingGroups) {
                final StringBuilder sb = new StringBuilder(value.length() + 1);
                final int groupStart = backRefMatcher.start(1);

                sb.append(value.substring(0, groupStart - 1));
                sb.append("\\");
                sb.append(value.substring(groupStart - 1));
                value = sb.toString();
            }
        }

        return value;
    }

}
