
package uk.org.ukfederation.mda.upstream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Element;

import net.shibboleth.metadata.Item;
import net.shibboleth.metadata.ItemCollectionSerializer;
import net.shibboleth.metadata.dom.saml.EntitiesDescriptorDisassemblerStage;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import uk.org.ukfederation.mda.BaseDOMTest;

public class DiscoFeedCollectionSerializerTest extends BaseDOMTest {

    protected DiscoFeedCollectionSerializerTest() {
        super(DiscoFeedCollectionSerializer.class);
    }

    @Test
    public void testEmptyCollection() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();
        final String output;
        try (final ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            ser.serializeCollection(new ArrayList<Item<Element>>(), out);
            output = out.toString();
        }
        final JsonReader read = Json.createReader(new StringReader(output));
        final JsonArray array = read.readArray();
        Assert.assertEquals(array.size(), 0);
    }

    private JsonArray fetchJSONArray(@Nonnull final String path) throws IOException {
        try (InputStream in = BaseDOMTest.class.getResourceAsStream(classRelativeResource(path))) {
            try (JsonReader reader = Json.createReader(in)) {
                return reader.readArray();
            }
        }        
    }

    private void checkEntity(@Nonnull final JsonObject entity) {
        Assert.assertEquals(entity.getString("entityID"), "https://idp.example.com/idp/shibboleth");
    }

    private void checkEntityArray(@Nonnull final JsonArray array) {
        Assert.assertEquals(array.size(), 1);
        checkEntity((JsonObject)array.get(0));
    }

    @Test
    public void testPreCooked() throws Exception {
        JsonArray entity = fetchJSONArray("base.json");
        checkEntityArray(entity);
    }

    private void compareCollections(@Nonnull final JsonArray actual, @Nonnull final JsonArray expected) {
        // The two collections must match as to size
        if (actual.size() != expected.size()) {
            Assert.assertEquals(actual.size(), expected.size(), "array sizes differ");
        }
        // The two collections must match entity by entity
        for (int i = 0; i < actual.size(); i++) {
            final JsonObject actualEntity = (JsonObject)actual.get(i);
            final JsonObject expectedEntity = (JsonObject)expected.get(i);

            // Get an identifier for the entity
            final String id = "entity " + i + " ('" + expectedEntity.getString("entityID") + "')";

            // Compare the key sets
            final Set<String> actualKeys = actualEntity.keySet();
            final Set<String> expectedKeys = expectedEntity.keySet();
            Assert.assertEquals(actualKeys, expectedKeys, "key sets differ for " + id);

            // Key sets are the same... compare each key value
            for (final String key : actualKeys) {
                final JsonValue actualValue = actualEntity.get(key);
                final JsonValue expectedValue = expectedEntity.get(key);
                Assert.assertEquals(actualValue, expectedValue, "key " + key + " differs for " + id);
            }

            // Backstop
            Assert.assertEquals(actualEntity, expectedEntity, id + " differs:");
        }
    }

    /**
     * Checks the serialization of a single entity using a given serializer
     * configuration.
     * 
     * @param name base name for the resources
     * @param ser configured and initialized serializer to use
     * 
     * @return the single {@link JsonObject} for further tests
     * 
     * @throws IOException if there are parsing issues with the JSON file
     * @throws XMLParserException if there are parsing issues with the XML file
     */
    private JsonObject checkSingle(@Nonnull final String name, @Nonnull final ItemCollectionSerializer<Element> ser)
            throws IOException, XMLParserException {
        final String output;
        try (final ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            List<Item<Element>> items = new ArrayList<>();
            items.add(readDOMItem(name + ".xml"));
            ser.serializeCollection(items, out);
            output = out.toString();
        }
        //System.out.println(output);
        final JsonReader read = Json.createReader(new StringReader(output));
        final JsonArray array = read.readArray();
        Assert.assertEquals(array.size(), 1);
        
        final JsonObject entity = (JsonObject)array.get(0);
        checkEntity(entity);
        final JsonArray expected = fetchJSONArray(name + ".json");
        compareCollections(array, expected);
        Assert.assertEquals(array, expected);
        
        return entity;
    }

    // Test the base case, derived from a single standard IdP
    // with default generator settings.
    @Test
    public void testBase() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();
        final JsonObject entity = checkSingle("base", ser);
        Assert.assertTrue(entity.containsKey("Descriptions"));
        Assert.assertTrue(entity.containsKey("DisplayNames"));
        Assert.assertFalse(entity.containsKey("InformationURLs"));
        Assert.assertFalse(entity.containsKey("PrivacyStatementURLs"));
    }

    // Test the absence of an mdui:DisplayName
    // with default generator settings.
    @Test
    public void testNoLegacy() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();
        final JsonObject entity = checkSingle("nolegacy", ser);
        Assert.assertFalse(entity.containsKey("Descriptions"));
        Assert.assertFalse(entity.containsKey("DisplayNames"));
    }

    // Test the inclusion of a legacy DisplayName when the
    // serializer is set to allow this.
    @Test
    public void testLegacy() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.setIncludingLegacyDisplayNames(true);
        ser.setPrettyPrinting(true);
        ser.initialize();
        final JsonObject entity = checkSingle("legacy", ser);
        Assert.assertFalse(entity.containsKey("Descriptions"));
        Assert.assertTrue(entity.containsKey("DisplayNames"));
    }

    // Test an entity with a couple of InformationURLs.
    @Test
    public void testInformationURLs() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();
        final JsonObject entity = checkSingle("infourl", ser);
        Assert.assertTrue(entity.containsKey("Descriptions"));
        Assert.assertTrue(entity.containsKey("DisplayNames"));
        Assert.assertTrue(entity.containsKey("InformationURLs"));
    }

    // Test an entity with a couple of PrivacyStatementURLs.
    @Test
    public void testPrivacyStatementURLs() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();
        final JsonObject entity = checkSingle("privacyurl", ser);
        Assert.assertTrue(entity.containsKey("Descriptions"));
        Assert.assertTrue(entity.containsKey("DisplayNames"));
        Assert.assertTrue(entity.containsKey("PrivacyStatementURLs"));
    }

    // Test the optional nature of xml:lang on mdui:Logo elements.
    @Test
    public void testLogoLang() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();
        final JsonObject entity = checkSingle("logolang", ser);
        final JsonArray logos = entity.getJsonArray("Logos");
        Assert.assertEquals(logos.size(), 3);
        Assert.assertFalse(logos.getJsonObject(0).containsKey("lang"));
        Assert.assertTrue(logos.getJsonObject(1).containsKey("lang"));
        Assert.assertEquals(logos.getJsonObject(1).getString("lang"), "en");
        Assert.assertFalse(logos.getJsonObject(2).containsKey("lang"));
    }
    
    // Test entity attributes present (base tests absent)
    @Test
    public void testEntityAttributes() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.setIncludingEntityAttributes(true);
        ser.initialize();
        final JsonObject entity = checkSingle("entattr", ser);
        final JsonArray attrs = entity.getJsonArray("EntityAttributes");
        Assert.assertEquals(attrs.size(), 3);
        Assert.assertEquals(attrs.getJsonObject(2).getString("name"), "something");
        Assert.assertEquals(attrs.getJsonObject(2).getJsonArray("values").size(), 1);
        Assert.assertEquals(attrs.getJsonObject(2).getJsonArray("values").getString(0), "whatever");
    }

    // Test a large aggregate. This test is normally disabled, but it
    // can be brought back to life if necessary to test a new corpus.
    @Test(enabled=false)
    public void testAll() throws Exception {
        final DiscoFeedCollectionSerializer ser = new DiscoFeedCollectionSerializer();
        ser.initialize();

        // Build a collection to serialize.
        final Item<Element> item = readDOMItem("all.xml");
        final List<Item<Element>> items = new ArrayList<Item<Element>>();
        items.add(item);
        
        // Disaggregate the collection into individual entities
        final EntitiesDescriptorDisassemblerStage disassembler = new EntitiesDescriptorDisassemblerStage();
        disassembler.setId("disassemble");
        disassembler.initialize();
        disassembler.execute(items);
        
        // Now generate the disco feed
        final String output;
        try (final ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            ser.serializeCollection(items, out);
            output = out.toString();
        }
        final JsonReader read = Json.createReader(new StringReader(output));
        final JsonArray array = read.readArray();

        final JsonArray expected = fetchJSONArray("all.json");
        compareCollections(array, expected);
        Assert.assertEquals(array, expected);
    }
}