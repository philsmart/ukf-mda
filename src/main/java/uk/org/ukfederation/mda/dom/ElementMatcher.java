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

package uk.org.ukfederation.mda.dom;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.xml.ElementSupport;

import org.w3c.dom.Element;

import com.google.common.base.Predicate;

/**
 * Basic matcher class for {@link Element}s for use with the {@link Container} system.
 */
@ThreadSafe
public class ElementMatcher implements Predicate<Element> {

    /** Element {@link QName} to match. */
    @Nonnull private final QName qname;
    
    /**
     * Constructor.
     * 
     * @param qnameToMatch qualified name ({@link QName}) to match
     */
    public ElementMatcher(@Nullable final QName qnameToMatch) {
        assert qnameToMatch != null;
        qname = qnameToMatch;
    }
    
    @Override
    public boolean apply(Element input) {
        return ElementSupport.isElementNamed(input, qname);
    }
    
}
