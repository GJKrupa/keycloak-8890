package dev.krupa.keycloak.keycloak8890;

import org.apache.commons.io.FileUtils;
import org.junit.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.*;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.Platform;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.remote.BrowserType;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.equalTo;

public class LogoutIdTokenTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogoutIdTokenTest.class);

    private Keycloak keycloak;

    private String clientSecret;
    private RemoteWebDriver chromeDriver;

    @ClassRule
    public static final Network NETWORK = Network.newNetwork();

    @ClassRule
    public static final GenericContainer CHROME = new GenericContainer("selenium/standalone-chrome:3.141.59-mercury")
            .withNetwork(NETWORK)
            .withExposedPorts(4444)
            .withSharedMemorySize(2147483648L)
            .withLogConsumer(new Slf4jLogConsumer(LOGGER).withPrefix("CHROME"))
            .waitingFor(new LogMessageWaitStrategy().withRegEx("(?m).*Selenium Server is up and running on port.*").withStartupTimeout(Duration.ofSeconds(30)))
            .withNetworkAliases("grid-chrome");

    @ClassRule
    public static final GenericContainer KEYCLOAK = new GenericContainer("jboss/keycloak:4.8.3.Final")
            .withEnv("KEYCLOAK_USER", "admin")
            .withEnv("KEYCLOAK_PASSWORD", "password")
            .withNetwork(NETWORK)
            .withNetworkAliases("keycloak")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER).withPrefix("KC"))
            .waitingFor(new LogMessageWaitStrategy().withRegEx("(?m).*Started \\d+ of \\d+ services.*").withStartupTimeout(Duration.ofSeconds(30)))
            .withExposedPorts(8080);

    @ClassRule
    public static final GenericContainer SERVER = new GenericContainer("nginxdemos/hello:0.2")
            .withNetwork(NETWORK)
            .withNetworkAliases("server")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER).withPrefix("SERVER"));

    private final GenericContainer proxy = new GenericContainer("quay.io/ukhomeofficedigital/go-keycloak-proxy:v2.3.0")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER).withPrefix("PROXY"))
            .waitingFor(new LogMessageWaitStrategy().withRegEx("(?m).*keycloak proxy service starting.*").withStartupTimeout(Duration.ofSeconds(30)))
            .withNetwork(NETWORK)
            .withNetworkAliases("proxy");

    @BeforeClass
    public static void deleteScreenshots() {
        try {
            FileUtils.deleteDirectory(new File("./screenshots"));
        } catch (IOException e) {
            LOGGER.error("Unable to delete screenshots directory");
        }
    }

    @Before
    public void createRealm() {
        keycloak = KeycloakBuilder.builder()
                .serverUrl(String.format("http://%s:%d/auth", KEYCLOAK.getContainerIpAddress(), KEYCLOAK.getMappedPort(8080)))
                .realm("master")
                .clientId("admin-cli")
                .username("admin").password("password")
                .build();

        final RealmResource testRealm = createRealm(keycloak);
        createUser(testRealm);

        ClientResource testClient = createClient(testRealm);
        addAudClaim(testClient);
        clientSecret = testClient.getSecret().getValue();

        chromeDriver = (RemoteWebDriver) RemoteWebDriver.builder()
                .setCapability(CapabilityType.BROWSER_NAME, BrowserType.CHROME)
                .setCapability(CapabilityType.PLATFORM_NAME, Platform.LINUX.name())
                .url(String.format("http://%s:%d/wd/hub", CHROME.getContainerIpAddress(), CHROME.getMappedPort(4444)))
                .build();
    }

    private ClientResource createClient(RealmResource testRealm) {
        ClientRepresentation client = new ClientRepresentation();
        client.setName("testClient");
        client.setClientId("testClient");
        client.setDirectAccessGrantsEnabled(true);
        client.setServiceAccountsEnabled(true);
        client.setAuthorizationServicesEnabled(true);
        client.setBaseUrl("http://localhost:8000");
        client.setWebOrigins(Collections.singletonList("http://proxy:8000/*"));
        client.setRedirectUris(Collections.singletonList("http://proxy:8000/*"));
        testRealm.clients().create(client);
        String id = testRealm.clients().findByClientId("testClient").get(0).getId();
        return testRealm.clients().get(id);
    }

    private void addAudClaim(ClientResource client) {
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("aud");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-hardcoded-claim-mapper");
        Map<String,String> config = new HashMap<>();
        config.put("userinfo.token.claim", Boolean.TRUE.toString());
        config.put("id.token.claim", Boolean.TRUE.toString());
        config.put("access.token.claim", Boolean.TRUE.toString());
        config.put("claim.name", "aud");
        config.put("claim.value", "testClient");
        config.put("jsonType.label", "String");
        mapper.setConfig(config);
        client.getProtocolMappers().createMapper(mapper);
    }

    private void createUser(RealmResource testRealm) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("bob");
        user.setEmail("bob@home.com");
        user.setEnabled(true);
        user.setFirstName("Bob");
        user.setLastName("Alice");
        testRealm.users().create(user);

        String userId = testRealm.users().search("bob").get(0).getId();
        final CredentialRepresentation creds = new CredentialRepresentation();
        creds.setType(CredentialRepresentation.PASSWORD);
        creds.setTemporary(false);
        creds.setValue("alice");
        testRealm.users().get(userId).resetPassword(creds);
    }

    private RealmResource createRealm(Keycloak keycloak) {
        RealmRepresentation realm = new RealmRepresentation();
        realm.setDisplayName("test");
        realm.setRealm("test");
        realm.setEnabled(true);
        keycloak.realms().create(realm);
        return keycloak.realm("test");
    }

    @Test
    public void testNonRefreshToken() {
        proxy
                .withCommand(
                        "--listen=0.0.0.0:8000",
                        "--redirection-url=http://proxy:8000",
                        "--discovery-url=http://keycloak:8080/auth/realms/test/.well-known/openid-configuration",
                        "--client-id=testClient",
                        "--client-secret=" + clientSecret,
                        "--resources=uri=/*",
                        "--upstream-url=http://server:80",
                        "--verbose=true",
                        "--enable-login-handler=true",
                        "--enable-token-header=false",
                        "--enable-authorization-header=true",
                        "--enable-authorization-cookies=false",
                        "--secure-cookie=false"
                )
                .start();

        chromeDriver.navigate().to("http://proxy:8000/test");
        saveScreenshot("non-refresh/1.png");
        chromeDriver.findElementById("username").sendKeys("bob");
        chromeDriver.findElementById("password").sendKeys("alice");
        chromeDriver.findElementById("kc-login").click();
        saveScreenshot("non-refresh/2.png");
        chromeDriver.navigate().to("http://proxy:8000/oauth/logout?redirect=http://proxy:8000/gone");
        saveScreenshot("non-refresh/3.png");
        Assert.assertThat(chromeDriver.findElementsById("username").size(), equalTo(1));
    }

    @Test
    public void testWithRefreshToken() {
        proxy
                .withCommand(
                        "--listen=0.0.0.0:8000",
                        "--redirection-url=http://proxy:8000",
                        "--discovery-url=http://keycloak:8080/auth/realms/test/.well-known/openid-configuration",
                        "--client-id=testClient",
                        "--client-secret=" + clientSecret,
                        "--resources=uri=/*",
                        "--upstream-url=http://server:80",
                        "--verbose=true",
                        "--enable-login-handler=true",
                        "--enable-token-header=false",
                        "--enable-authorization-header=true",
                        "--enable-authorization-cookies=false",
                        "--secure-cookie=false",
                        "--enable-refresh-tokens=true",
                        "--encryption-key=12345678901234567890123456789012"
                )
                .start();

        chromeDriver.navigate().to("http://proxy:8000/test");
        saveScreenshot("refresh/1.png");
        chromeDriver.findElementById("username").sendKeys("bob");
        chromeDriver.findElementById("password").sendKeys("alice");
        chromeDriver.findElementById("kc-login").click();
        saveScreenshot("refresh/2.png");
        chromeDriver.navigate().to("http://proxy:8000/oauth/logout?redirect=http://proxy:8000/gone");
        saveScreenshot("refresh/3.png");
        Assert.assertThat(chromeDriver.findElementsById("username").size(), equalTo(1));
    }

    private void saveScreenshot(String filename) {
        final File screenshot = ((TakesScreenshot) chromeDriver).getScreenshotAs(OutputType.FILE);
        LOGGER.info(screenshot.getAbsolutePath());
        try {
            FileUtils.moveFile(screenshot, new File("./screenshots/" + filename));
        } catch (IOException e) {
            LOGGER.error("Failed to move screenshot", e);
        }
    }

    @After
    public void tearDown() {
        proxy.stop();
        keycloak.realm("test").remove();
    }

}
