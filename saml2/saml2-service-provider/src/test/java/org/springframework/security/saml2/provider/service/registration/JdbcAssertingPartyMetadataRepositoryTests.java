package org.springframework.security.saml2.provider.service.registration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.serializer.DefaultSerializer;
import org.springframework.core.serializer.Serializer;
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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.security.saml2.provider.service.registration.JdbcAssertingPartyMetadataRepository.SAVE_SQL;

/**
 * Tests for {@link JdbcAssertingPartyMetadataRepository}
 */
class JdbcAssertingPartyMetadataRepositoryTests {

	private static final String SCHEMA_SQL_RESOURCE = "org/springframework/security/saml2/saml2-asserting-party-metadata-schema.sql";

	private static final String ENTITY_ID = "https://localhost/simplesaml/saml2/idp/metadata.php";

	private static final String SINGLE_SIGNON_URL = "https://localhost/SSO";

	private static final String SINGLE_SIGNON_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private static final String SINGLE_SIGNON_SIGN_REQUEST = "true";

	private static final String SINGLE_LOGOUT_URL = "https://localhost/SLO";

	private static final String SINGLE_LOGOUT_RESPONSE_URL = "https://localhost/SLO/response";

	private static final String SINGLE_LOGOUT_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private static final List<String> SIGNING_ALGORITHMS = List.of("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

	private X509Certificate certificate;

	private String metadataUri;

	private EmbeddedDatabase db;

	private JdbcAssertingPartyMetadataRepository repository;

	private JdbcOperations jdbcOperations;

	private final MockWebServer mockWebServer = new MockWebServer();

	private final Serializer<Object> serializer = new DefaultSerializer();

	@BeforeEach
	public void setUp() throws Exception {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcAssertingPartyMetadataRepository(this.jdbcOperations);
		this.certificate = loadCertificate("rsa.crt");

		ClassPathResource resource = new ClassPathResource("test-federated-metadata.xml");
		String metadata;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			metadata = reader.lines().collect(Collectors.joining());
		}

		this.mockWebServer.enqueue(new MockResponse().setBody(metadata).setResponseCode(200));
		this.metadataUri = this.mockWebServer.url("/metadata").toString();
	}

	@AfterEach
	public void tearDown() throws IOException {
		this.db.shutdown();
		this.mockWebServer.close();
	}

	@Test
	void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcAssertingPartyMetadataRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	void findByRegistrationIdWhenEntityIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.findByEntityId(null))
				.withMessage("entityId cannot be empty");
		// @formatter:on
	}

	@Test
	void findByEntityIdWhenAssertingpartyMetadataUriExists() {
		this.jdbcOperations.update(SAVE_SQL, ENTITY_ID, metadataUri, null, null,
				null, null, null, null, null, null, null);

		AssertingPartyMetadata found = repository.findByEntityId(ENTITY_ID);

		assertThat(found).isNotNull();
		assertThat(found.getSingleSignOnServiceLocation()).isNotEqualTo(SINGLE_SIGNON_URL);
		assertThat(found.getSigningAlgorithms()).contains(SIGNING_ALGORITHMS.get(0));
		assertThat(found.getVerificationX509Credentials()).isNotEmpty();
		assertThat(found.getEncryptionX509Credentials()).isNotEmpty();
	}

	@Test
	void findByEntityId() throws IOException {
		this.jdbcOperations.update(SAVE_SQL, ENTITY_ID, metadataUri, SINGLE_SIGNON_URL, SINGLE_SIGNON_BINDING,
				SINGLE_SIGNON_SIGN_REQUEST, this.serializer.serializeToByteArray(SIGNING_ALGORITHMS),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)),
				SINGLE_LOGOUT_URL, SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING);

		AssertingPartyMetadata found = repository.findByEntityId(ENTITY_ID);

		assertThat(found).isNotNull();
		assertThat(found.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(found.getSingleSignOnServiceLocation()).isEqualTo(SINGLE_SIGNON_URL);
		assertThat(found.getSingleSignOnServiceBinding().getUrn()).isEqualTo(SINGLE_SIGNON_BINDING);
		assertThat(found.getWantAuthnRequestsSigned()).isEqualTo(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST));
		assertThat(found.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(found.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(found.getSingleLogoutServiceBinding().getUrn()).isEqualTo(SINGLE_LOGOUT_BINDING);
		assertThat(found.getSigningAlgorithms()).contains(SIGNING_ALGORITHMS.get(0));
		assertThat(found.getVerificationX509Credentials()).isNotEmpty();
		assertThat(found.getEncryptionX509Credentials()).isNotEmpty();
	}

	@Test
	void findByEntityIdWhenNotExists() {
		AssertingPartyMetadata found = repository.findByEntityId("non-existent-entity-id");
		assertThat(found).isNull();
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
		} catch (Exception ex) {
			throw new RuntimeException("Error loading certificate from " + path, ex);
		}
	}

	private RSAPrivateKey loadPrivateKey(String path) {
		try (InputStream is = new ClassPathResource(path).getInputStream()) {
			return RsaKeyConverters.pkcs8().convert(is);
		} catch (Exception ex) {
			throw new RuntimeException("Error loading private key from " + path, ex);
		}
	}

	private Collection<Saml2X509Credential> asCredentials(X509Certificate certificate) {
		return List.of(new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
				Saml2X509Credential.Saml2X509CredentialType.VERIFICATION));
	}
}
