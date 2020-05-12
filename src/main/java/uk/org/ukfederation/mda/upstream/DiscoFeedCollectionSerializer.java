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

package uk.org.ukfederation.mda.upstream;

import java.io.OutputStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.json.Json;
import javax.json.stream.JsonGenerator;
import javax.json.stream.JsonGeneratorFactory;
import javax.xml.namespace.QName;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import net.shibboleth.metadata.Item;
import net.shibboleth.metadata.ItemCollectionSerializer;
import net.shibboleth.metadata.dom.saml.mdattr.MDAttrSupport;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;
import uk.org.ukfederation.mda.dom.saml.SAMLSupport;

/**
 * A collection serializer that generates an equivalent of the Shibboleth SP's discovery
 * feed output from a collection of entity descriptors.
 */
public class DiscoFeedCollectionSerializer extends AbstractInitializableComponent
    implements ItemCollectionSerializer<Element> {

    /** Configured JSON generator factory. */
    @NonnullAfterInit
    private JsonGeneratorFactory factory;

    /** Whether to pretty-print the resulting JSON. Default: <code>false</code> */
    private boolean prettyPrinting;

    /**
     * Whether to include legacy display names if none are found in the
     * <code>mdui:UIInfo</code> element.
     * 
     * Default: <code>false</code>
     */
    private boolean includingLegacyDisplayNames;
    
    /** Whether to include entity attributes. Default: <code>false</code> */
    private boolean includingEntityAttributes;

    /**
     * Returns whether output is being pretty-printed.
     * 
     * @return whether output is being pretty-printed
     */
    public boolean isPrettyPrinting() {
        return prettyPrinting;
    }

    /**
     * Sets whether to pretty-print the output.
     * 
     * @param pretty whether to pretty-print the output
     */
    public void setPrettyPrinting(final boolean pretty) {
        prettyPrinting = pretty;
    }

    /**
     * Returns whether output includes legacy display names.
     * 
     * @return whether output includes legacy display names
     */
    public boolean isIncludingLegacyDisplayNames() {
        return includingLegacyDisplayNames;
    }

    /**
     * Sets whether to include legacy display names.
     * 
     * @param includeLegacyDisplayNames whether to include legacy display names
     */
    public void setIncludingLegacyDisplayNames(final boolean includeLegacyDisplayNames) {
        includingLegacyDisplayNames = includeLegacyDisplayNames;
    }

    /**
     * Returns whether output includes entity attributes.
     * 
     * @return whether output includes entity attributes
     */
    public boolean isIncludingEntityAttributes() {
        return includingEntityAttributes;
    }

    /**
     * Sets whether to include entity attributes.
     * 
     * @param includeEntityAttributes whether to include entity attributes.
     */
    public void setIncludingEntityAttributes(final boolean includeEntityAttributes) {
        includingEntityAttributes = includeEntityAttributes;
    }

    /**
     * Find the first <code>mdui:UIInfo</code> {@link Element} across a list of
     * <code>md:IDPSSODescriptor</code>s.
     *
     * @param idpDescriptors list of <code>md:IDPSSODescriptor</code>s
     *
     * @return the first <code>mdui:UIInfo</code> element, or <code>null</code> if none are found
     */
    @Nullable
    private Element findFirstUIInfo(@Nonnull @NonnullElements final List<Element> idpDescriptors) {
        for (final Element idpDescriptor : idpDescriptors) {
            final Element uiInfo = SAMLMetadataSupport.getDescriptorExtension(idpDescriptor, MDUISupport.UIINFO_NAME);
            if (uiInfo != null) {
                return uiInfo;
            }
        }
        return null;
    }

    /**
     * Write a list of element values and language tags to the output
     * as a JSON array under a given key.
     * 
     * @param gen the {@link JsonGenerator} to write the output to
     * @param elements list of {@link Element}s to write out
     * @param key key for the JSON array within the containing object
     */
    private void writeValueLangList(@Nonnull final JsonGenerator gen,
            @Nonnull @NonnullElements final List<Element> elements,
            @Nonnull final String key) {
        gen.writeStartArray(key);
        for (final Element element : elements) {
            gen.writeStartObject();
                gen.write("value", element.getTextContent());
                gen.write("lang", element.getAttribute("xml:lang"));
            gen.writeEnd();
        }
        gen.writeEnd();
    }

    /**
     * Write a value/language list for elements within a <code>mdui:UIInfo</code> container.
     * 
     * @param gen the {@link JsonGenerator} to write the output to
     * @param uiInfo the <code>mdui:UIInfo</code> element
     * @param elementName name of the elements to collect from
     * @param key key for the JSON array within the containing object
     */
    private void writeValueLangList(@Nonnull final JsonGenerator gen,
            @Nonnull final Element uiInfo,
            @Nonnull final QName elementName,
            @Nonnull final String key) {
        final List<Element> elements = ElementSupport.getChildElements(uiInfo, elementName);
        if (!elements.isEmpty()) {
            writeValueLangList(gen, elements, key);
        }        
    }
    
    /**
     * Write out an entity's entity attributes.
     *
     * @param gen the {@link JsonGenerator} to write the output to
     * @param entity the <code>md:EntityDescriptor</code> element
     */
    private void writeEntityAttributes(@Nonnull final JsonGenerator gen, @Nonnull final Element entity) {
        final Element ext = SAMLMetadataSupport.getDescriptorExtension(entity, MDAttrSupport.ENTITY_ATTRIBUTES_NAME);
        if (ext != null) {
            final List<Element> attributes = ElementSupport.getChildElements(ext, SAMLSupport.ATTRIBUTE_NAME);
            if (!attributes.isEmpty()) {
                gen.writeStartArray("EntityAttributes");
                    for (final Element attribute : attributes) {
                        final List<Element> values =
                                ElementSupport.getChildElements(attribute, SAMLSupport.ATTRIBUTE_VALUE_NAME);
                        if (!values.isEmpty()) {
                            gen.writeStartObject();
                                gen.write("name", attribute.getAttribute("Name"));
                                gen.writeStartArray("values");
                                    for (final Element value : values) {
                                        gen.write(value.getTextContent());
                                    }
                                gen.writeEnd();
                            gen.writeEnd();
                        }
                    }
                gen.writeEnd();
            }
        }
    }

    /**
     * Write the entity's logos to the output.
     *
     * @param gen the {@link JsonGenerator} to write the output to
     * @param uiInfo the <code>mdui:UIInfo</code> element
     */
    private void writeLogos(@Nonnull final JsonGenerator gen, @Nonnull final Element uiInfo) {
        final List<Element> logos = ElementSupport.getChildElements(uiInfo, MDUISupport.LOGO_NAME);
        if (!logos.isEmpty()) {
            gen.writeStartArray("Logos");
                for (final Element logo: logos) {
                    gen.writeStartObject();
                        gen.write("value", logo.getTextContent());
                        gen.write("height", logo.getAttribute("height"));
                        gen.write("width", logo.getAttribute("width"));
                        // xml:lang is optional on mdui:Logo elements
                        final Attr lang = logo.getAttributeNode("xml:lang");
                        if (lang != null) {
                            gen.write("lang", lang.getTextContent());
                        }
                    gen.writeEnd();
                }
            gen.writeEnd();
        }
    }

    /**
     * Write the list of display names to the output.
     *
     * If we have a <code>mdui:UIInfo</code>, we may be able to find some display names
     * there. If we can find no <code>mdui:DisplayName</code> elements, we instead
     * find legacy display names in the <code>md:Organization</code> element.
     *
     * @param gen the {@link JsonGenerator} to write the output to
     * @param entity <code>md:EntityDescriptor</code> element
     * @param uiInfo <code>mdui:UIInfo</code> if available, or <code>null</code>
     */
    private void writeDisplayNames(@Nonnull final JsonGenerator gen, @Nonnull final Element entity,
            @Nullable final Element uiInfo) {
        // Attempt to find display names in the mdui:UIInfo element
        if (uiInfo != null) {
            final List<Element> displayNames = ElementSupport.getChildElements(uiInfo, MDUISupport.DISPLAYNAME_NAME);
            if (!displayNames.isEmpty()) {
                writeValueLangList(gen, displayNames, "DisplayNames");
                // We have found our display names
                return;
            }
        }
        
        // Attempt to find display names elsewhere
        if (includingLegacyDisplayNames) {
            final Element org = ElementSupport.getFirstChildElement(entity, SAMLMetadataSupport.ORGANIZATION_NAME);
            if (org != null) {
                final List<Element> displayNames =
                        ElementSupport.getChildElements(org, SAMLMetadataSupport.ORGANIZATIONDISPLAYNAME_NAME);
                if (!displayNames.isEmpty()) {
                    writeValueLangList(gen, displayNames, "DisplayNames");
                }
            }
        }
    }

    @Override
    public void serializeCollection(@Nonnull @NonnullElements final Collection<Item<Element>> items,
            @Nonnull final OutputStream output) {
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        final JsonGenerator gen = factory.createGenerator(output);
        gen.writeStartArray();
            for (final Item<Element> item : items) {
                final Element entity = item.unwrap();
                if (SAMLMetadataSupport.isEntityDescriptor(entity)) {
                    final List<Element> idpDescriptors =
                            ElementSupport.getChildElements(entity, SAMLMetadataSupport.IDP_SSO_DESCRIPTOR_NAME);
                    if (!idpDescriptors.isEmpty()) {
                        gen.writeStartObject();
                            gen.write("entityID", entity.getAttributeNS(null, "entityID"));
                            final Element uiInfo = findFirstUIInfo(idpDescriptors);
                            writeDisplayNames(gen, entity, uiInfo);
                            if (uiInfo != null) {
                                writeValueLangList(gen, uiInfo, MDUISupport.DESCRIPTION_NAME, "Descriptions");
                                writeValueLangList(gen, uiInfo, MDUISupport.KEYWORDS_NAME, "Keywords");
                                writeValueLangList(gen, uiInfo, MDUISupport.INFORMATIONURL_NAME, "InformationURLs");
                                writeValueLangList(gen, uiInfo,
                                        MDUISupport.PRIVACYSTATEMENTURL_NAME, "PrivacyStatementURLs");
                                writeLogos(gen, uiInfo);
                            }
                            if (includingEntityAttributes) {
                                writeEntityAttributes(gen, entity);
                            }
                        gen.writeEnd();
                    }
                }
            }
        gen.writeEnd();
        gen.close();
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        final Map<String, String> generatorConfig = new HashMap<>();
        if (prettyPrinting) {
            generatorConfig.put(JsonGenerator.PRETTY_PRINTING, "true");
        }
        factory = Json.createGeneratorFactory(generatorConfig);
    }

    @Override
    protected void doDestroy() {
        factory = null;
        super.doDestroy();
    }

}
