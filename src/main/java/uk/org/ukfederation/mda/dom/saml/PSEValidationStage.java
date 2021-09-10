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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import com.google.common.collect.ImmutableSet;

import net.shibboleth.metadata.ErrorStatus;
import net.shibboleth.metadata.Item;
import net.shibboleth.metadata.dom.saml.SAMLMetadataSupport;
import net.shibboleth.metadata.pipeline.BaseIteratingStage;
import net.shibboleth.metadata.pipeline.StageProcessingException;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;

/**
 * A Stage which allows validation of the <code>protocolSupportEnumeration</code>
 * XML attribute on the named elements.
 */
@ThreadSafe
public class PSEValidationStage extends BaseIteratingStage<Element> {

    /** Collection of role descriptor names to process. */
    @Nonnull @NonnullElements @Unmodifiable @GuardedBy("this")
    private Set<QName> roleNames = Collections.emptySet();

    /** Set of permitted <code>protocolSupportEnumeration</code> tokens. */
    @Nonnull @NonnullElements @Unmodifiable @GuardedBy("this")
    private Set<String> validTokens = Collections.emptySet();

    /**
     * Returns the collection of role descriptor names to process.
     *
     * @return the collection of role descriptor names to process
     */
    @Nonnull @NonnullElements @Unmodifiable public synchronized Set<QName> getRoleNames() {
        return roleNames;
    }

    /**
     * Sets the collection of role descriptor names to process.
     *
     * @param roles the collection of role descriptor names to process
     */
    public synchronized void setRoleNames(@Nonnull @NonnullElements @Unmodifiable final Collection<QName> roles) {
        roleNames = ImmutableSet.copyOf(roles);
    }

    /**
     * Returns the permitted <code>protocolSupportEnumeration</code> tokens.
     *
     * @return the set of permitted tokens
     */
    @Nonnull @NonnullElements @Unmodifiable public synchronized Set<String> getValidTokens() {
        return validTokens;
    }

    /**
     * Sets the permitted <code>protocolSupportEnumeration</code> tokens.
     *
     * @param tokens collection of <code>protocolSupportEnumeration</code> tokens to be permitted
     */
    public synchronized void setValidTokens(@Nonnull @NonnullElements @Unmodifiable final Collection<String> tokens) {
        validTokens = ImmutableSet.copyOf(tokens);
    }

    @Override
    protected boolean doExecute(@Nonnull final Item<Element> item) throws StageProcessingException {
        final Element entity = item.unwrap();

        if (!SAMLMetadataSupport.isEntityDescriptor(entity)) {
            // Not an entity, just exit.
            return true;
        }

        // Snapshot bean state
        final Set<QName> roles = getRoleNames();
        final Set<String> tokens = getValidTokens();

        // Collect all the role descriptors to be processed.
        final List<Element> roleDescriptors = new ArrayList<>();
        for (final QName roleName : roles) {
            final List<Element> roleElements = ElementSupport.getChildElements(entity, roleName);
            roleDescriptors.addAll(roleElements);
        }

        // Process each role descriptor in turn
        for (final Element roleDescriptor : roleDescriptors) {
            final List<String> pSEValues = AttributeSupport.getAttributeValueAsList(
                            roleDescriptor.getAttributeNode("protocolSupportEnumeration"));
            for (final String uri : pSEValues) {
                if (!tokens.contains(uri)) {
                    final StringBuilder b = new StringBuilder(roleDescriptor.getLocalName());
                    b.append("/@protocolSupportEnumeration contains unknown token ");
                    b.append(uri);
                    item.getItemMetadata().put(new ErrorStatus(getId(), b.toString()));
                }
            }
        }

        return true;
    }

}
