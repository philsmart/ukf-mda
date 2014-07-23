
package uk.org.ukfederation.mda.dom.saml.mdattr;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.common.base.Predicate;

public class RegistrationAuthorityMatcherTest {

    private void test(final boolean expected, final Predicate<EntityAttributeContext> matcher,
            final EntityAttributeContext context) {
        Assert.assertEquals(expected, matcher.apply(context), context.toString());
    }
    
    @Test
    public void testWithRA() {
        final Predicate<EntityAttributeContext> matcher = new RegistrationAuthorityMatcher("registrar");
        
        test(true, matcher, new SimpleEntityAttributeContext("a", "b", "c", "registrar"));
        test(false, matcher, new SimpleEntityAttributeContext("a", "b", "c", "registrar2"));
        test(false, matcher, new SimpleEntityAttributeContext("a", "b", "c", null));
    }

    @Test
    public void testNoRA() {
        final Predicate<EntityAttributeContext> matcher = new RegistrationAuthorityMatcher(null);
        
        test(false, matcher, new SimpleEntityAttributeContext("a", "b", "c", "registrar"));
        test(false, matcher, new SimpleEntityAttributeContext("a", "b", "c", "registrar2"));
        test(true, matcher, new SimpleEntityAttributeContext("a", "b", "c", null));
    }

}
