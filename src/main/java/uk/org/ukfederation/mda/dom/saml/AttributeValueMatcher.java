/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.org.ukfederation.mda.dom.saml;

import javax.annotation.Nonnull;

import org.w3c.dom.Element;

import uk.org.ukfederation.mda.dom.ElementMatcher;

/**
 * Match {@link com.google.common.base.Predicate} for SAML <code>AttributeValue</code> elements with specific
 * text values,
 * for use with the {@link uk.org.ukfederation.mda.dom.Container} system.
 */
public class AttributeValueMatcher extends ElementMatcher {

    /** <code>Attribute</code> value to match. */
    @Nonnull private final String matchValue;
    
    /**
     * Constructor.
     * 
     * @param value <code>Attribute</code> value to match
     */
    public AttributeValueMatcher(@Nonnull final String value) {
        super(SAMLSupport.ATTRIBUTE_VALUE_NAME);
        assert value != null;
        matchValue = value;
    }

    @Override
    public boolean apply(@Nonnull final Element element) {
        // check for element name
        if (!super.apply(element)) {
            return false;
        }
        
        // now check attribute value
        return matchValue.equals(element.getTextContent());
    }
}