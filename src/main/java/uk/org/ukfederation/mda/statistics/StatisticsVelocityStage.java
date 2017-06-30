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

package uk.org.ukfederation.mda.statistics;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.app.VelocityEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.metadata.Item;
import net.shibboleth.metadata.dom.DOMElementItem;
import net.shibboleth.metadata.dom.saml.SAMLMetadataSupport;
import net.shibboleth.metadata.pipeline.AbstractStage;
import net.shibboleth.metadata.pipeline.StageProcessingException;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

/**
 * A stage implementation which generates statistics for a collection
 * of entities.
 */
@ThreadSafe
public class StatisticsVelocityStage extends AbstractStage<Element> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(StatisticsVelocityStage.class);
    
    /** Pool of parsers used to parse XML to DOM output. */
    private ParserPool parserPool;

    /** Name of the template to invoke for this stage. */
    private String templateName;

    /**
     * Gets the pool of DOM parsers used to parse XML to DOM.
     * 
     * @return pool of DOM parsers used to parse XML to DOM
     */
    @Nullable public ParserPool getParserPool() {
        return parserPool;
    }

    /**
     * Sets the pool of DOM parsers used to parse XML to DOM.
     * 
     * @param pool pool of DOM parsers used to parse XML to DOM
     */
    public synchronized void setParserPool(@Nonnull final ParserPool pool) {
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        parserPool = Constraint.isNotNull(pool, "parser pool may not be null");
    }

    /**
     * Gets the name of the template to invoke.
     * 
     * @return the name of the template to invoke.
     */
    @Nullable public String getTemplateName() {
        return templateName;
    }

    /**
     * Sets the name of the template to invoke.
     * 
     * @param name the name of the template to invoke.
     */
    public synchronized void setTemplateName(@Nonnull @NotEmpty final String name) {
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        templateName = Constraint.isNotNull(StringSupport.trimOrNull(name),
                "template name may not be null or empty");
    }


    /** {@inheritDoc} */
    @Override
    public void doExecute(final Collection<Item<Element>> collection) throws StageProcessingException {
        
        final VelocityEngine ve = new VelocityEngine();
        ve.setProperty("resource.loader", "class");
        ve.setProperty("class.resource.loader.description",
                "Velocity Classpath Resource Loader");
        ve.setProperty("class.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        ve.init();

        final VelocityContext context = new VelocityContext();
        context.put("name", new String("Velocity"));

        final Set<Item<Element>> entities = new HashSet<>(collection.size());
        
        for (Item<Element> item : collection) {
            if (SAMLMetadataSupport.isEntityDescriptor(item.unwrap())) {
                entities.add(item);
            }
        }
        context.put("entities", entities);
        
        final StringWriter w = new StringWriter();
        log.debug("merging template " + templateName);
        ve.mergeTemplate(templateName, Velocity.ENCODING_DEFAULT, context, w);
        log.debug("resulting string is " + w.toString());
        
        log.debug("parsing to DOM document");
        try {
            final Document doc = parserPool.parse(new StringReader(w.toString()));
            collection.clear();
            collection.add(new DOMElementItem(doc));
        } catch (XMLParserException e) {
            throw new StageProcessingException("could not parse template output", e);
        }
    }


    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (parserPool == null) {
            throw new ComponentInitializationException("parser pool may not be null");
        }

        if (templateName == null) {
            throw new ComponentInitializationException("template name may not be null or empty");
        }
        
    }

}
