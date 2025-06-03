package org.springframework.security.saml2.provider.service.registration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import static org.assertj.core.api.Assertions.assertThat;

class JdbcAssertingPartyMetadataRepositoryTest {

	private static final String SCHEMA_SQL_RESOURCE = "org/springframework/security/saml2/saml2-asserting-party-metadata-schema.sql";

	private static final String ENTITY_ID = "https://localhost/simplesaml/saml2/idp/metadata.php";

	private static final String SINGLE_SIGNON_URL = "https://localhost/SSO";

	private static final String SINGLE_SIGNON_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private static final String SINGLE_SIGNON_SIGN_REQUEST = "true";

	private static final String SINGLE_LOGOUT_URL = "https://localhost/SLO";

	private static final String SINGLE_LOGOUT_RESPONSE_URL = "https://localhost/SLO/response";

	private static final String SINGLE_LOGOUT_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private X509Certificate verificationCredentials;

	private EmbeddedDatabase db;

	private JdbcAssertingPartyMetadataRepository repository;

	private JdbcOperations jdbcOperations;

	private final MockWebServer mockWebServer = new MockWebServer();

	@BeforeEach
	public void setUp() throws Exception {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcAssertingPartyMetadataRepository(this.jdbcOperations);

		ClassPathResource resource = new ClassPathResource("test-federated-metadata.xml");
		String metadata;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			metadata = reader.lines().collect(Collectors.joining());
		}

		this.mockWebServer.enqueue(new MockResponse().setBody(metadata).setResponseCode(200));

		 verificationCredentials = loadCertificate("rsa.crt");
		RSAPrivateKey rsaPrivateKey = loadPrivateKey("rsa.key");
	}

	@AfterEach
	public void tearDown() throws IOException {
		this.db.shutdown();
		this.mockWebServer.close();
	}

	@Test
	void testSave() {
		RelyingPartyRegistration.AssertingPartyDetails details = new RelyingPartyRegistration.AssertingPartyDetails.Builder()
				.entityId(ENTITY_ID)
				.wantAuthnRequestsSigned(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST))
				.verificationX509Credentials(credentials -> credentials.add(asVerificationCredential(verificationCredentials)))
				.singleSignOnServiceLocation(SINGLE_SIGNON_URL)
				.singleSignOnServiceBinding(Saml2MessageBinding.from(SINGLE_SIGNON_BINDING))
				.singleLogoutServiceLocation(SINGLE_LOGOUT_URL)
				.singleLogoutServiceResponseLocation(SINGLE_LOGOUT_RESPONSE_URL)
				.singleLogoutServiceBinding(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING))
				.build();
		this.repository.save(details);

		AssertingPartyMetadata uniqueByEntityId = this.repository.findUniqueByEntityId(ENTITY_ID);
		assertThat(uniqueByEntityId).isNotNull();
	}

	private static EmbeddedDatabase createDb() {
		return createDb(SCHEMA_SQL_RESOURCE);
	}

	private static EmbeddedDatabase createDb(String schema) {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(schema)
				.build();
		// @formatter:on
	}

	private X509Certificate loadCertificate(String path) {
		try (InputStream is = new ClassPathResource(path).getInputStream()) {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) factory.generateCertificate(is);
		}
		catch (Exception ex) {
			throw new RuntimeException("Error loading certificate from " + path, ex);
		}
	}

	private RSAPrivateKey loadPrivateKey(String path) {
		try (InputStream is = new ClassPathResource(path).getInputStream()) {
			return RsaKeyConverters.pkcs8().convert(is);
		}
		catch (Exception ex) {
			throw new RuntimeException("Error loading private key from " + path, ex);
		}
	}

	private Saml2X509Credential asVerificationCredential(X509Certificate certificate) {
		return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
				Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
	}
}
