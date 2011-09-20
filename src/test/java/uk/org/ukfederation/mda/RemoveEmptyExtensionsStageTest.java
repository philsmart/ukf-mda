package uk.org.ukfederation.mda;

import java.util.ArrayList;
import java.util.List;

import net.shibboleth.metadata.dom.DomElementItem;

import org.testng.annotations.Test;
import org.w3c.dom.Element;

public class RemoveEmptyExtensionsStageTest extends BaseDomTest {

    @Test
    public void doExecute() throws Exception {
        Element doc = readXmlData("emptyExtensionsIn.xml");
        DomElementItem item = new DomElementItem(doc);
        List<DomElementItem> items = new ArrayList<DomElementItem>();
        items.add(item);
        
        NamespaceStrippingStage removeMdui = new NamespaceStrippingStage();
        removeMdui.setId("removeMdui");
        removeMdui.setNamespace("urn:oasis:names:tc:SAML:metadata:ui");
        removeMdui.initialize();
        removeMdui.execute(items);
        
        NamespaceStrippingStage removeUk = new NamespaceStrippingStage();
        removeUk.setId("removeUk");
        removeUk.setNamespace("http://ukfederation.org.uk/2006/11/label");
        removeUk.initialize();
        removeUk.execute(items);
        
        RemoveEmptyExtensionsStage stage = new RemoveEmptyExtensionsStage();
        stage.setId("emptyExtensionsTest");
        stage.initialize();
        stage.execute(items);
        
        Element out = readXmlData("emptyExtensionsOut.xml");
        assertXmlEqual(out, item.unwrap());
    }
}