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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

import org.w3c.dom.Element;

import com.google.common.collect.ImmutableSet;

import net.shibboleth.metadata.dom.AbstractElementVisitingStage;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;

/**
 * A Stage which allows validation of the <code>protocolSupportEnumeration</code>
 * XML attribute on the named elements.
 */
@ThreadSafe
public class PSEValidationStage extends AbstractElementVisitingStage {

    /** Set of permitted <code>protocolSupportEnumeration</code> tokens. */
    @Nonnull @NonnullElements @Unmodifiable @GuardedBy("this")
    private Set<String> validTokens = Collections.emptySet();

    /**
     * Returns the permitted <code>protocolSupportEnumeration</code> tokens.
     *
     * @return the set of permitted tokens
     */
    @Nonnull @NonnullElements @Unmodifiable public Set<String> getValidTokens() {
        return validTokens;
    }

    /**
     * Sets the permitted <code>protocolSupportEnumeration</code> tokens.
     *
     * @param tokens collection of <code>protocolSupportEnumeration</code> tokens to be permitted
     */
    public void setValidTokens(@Nonnull @NonnullElements @Unmodifiable final Collection<String> tokens) {
        validTokens = ImmutableSet.copyOf(tokens);
    }

    @Override
    protected void visit(@Nonnull final Element e, @Nonnull final TraversalContext context) {
        final List<String> pSEValues =
                AttributeSupport.getAttributeValueAsList(e.getAttributeNode("protocolSupportEnumeration"));
        for (final String uri : pSEValues) {
            if (!validTokens.contains(uri)) {
                final StringBuilder b = new StringBuilder(e.getLocalName());
                b.append("/@protocolSupportEnumeration contains unknown token ");
                b.append(uri);
                final Element entity = ancestorEntity(e);
                addError(context.getItem(), entity, b.toString());
            }
        }
    }

}
