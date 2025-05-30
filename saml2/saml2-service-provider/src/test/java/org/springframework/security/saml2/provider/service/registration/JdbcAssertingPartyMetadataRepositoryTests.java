package org.springframework.security.saml2.provider.service.registration;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
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

import static org.assertj.core.api.Assertions.assertThat;

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

	private EmbeddedDatabase db;

	private JdbcAssertingPartyMetadataRepository repository;

	private JdbcOperations jdbcOperations;

	@BeforeEach
	public void setUp() throws Exception {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcAssertingPartyMetadataRepository(this.jdbcOperations);
		this.certificate = loadCertificate("rsa.crt");
	}

	@AfterEach
	public void tearDown() {
		this.db.shutdown();
	}

	@Test
	void saveAndFindByEntityId() {
		AssertingPartyMetadata metadata = assertingPartyMetadata();

		repository.save(metadata);
		AssertingPartyMetadata found = repository.findByEntityId(ENTITY_ID);

		assertThat(found).isNotNull();
		assertThat(found.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(found.getSingleSignOnServiceLocation()).isEqualTo(SINGLE_SIGNON_URL);
		assertThat(found.getSingleSignOnServiceBinding().getUrn()).isEqualTo(SINGLE_SIGNON_BINDING);
		assertThat(found.getWantAuthnRequestsSigned()).isEqualTo(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST));
		assertThat(found.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(found.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(found.getSingleLogoutServiceBinding().getUrn()).isEqualTo(SINGLE_LOGOUT_BINDING);
		assertThat(found.getSigningAlgorithms()).contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		assertThat(found.getVerificationX509Credentials()).isNotEmpty();
		assertThat(found.getEncryptionX509Credentials()).isNotEmpty();
	}

	@Test
	void updateExistingMetadata() {
		AssertingPartyMetadata metadata = assertingPartyMetadata();
		repository.save(metadata);

		AssertingPartyMetadata updatedMetadata = new RelyingPartyRegistration.AssertingPartyDetails.Builder()
				.entityId(ENTITY_ID)
				.wantAuthnRequestsSigned(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST))
				.signingAlgorithms(signingAlgorithms -> signingAlgorithms.addAll(SIGNING_ALGORITHMS))
				.verificationX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.encryptionX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.singleSignOnServiceLocation("https://localhost/SSO/updated")
				.singleSignOnServiceBinding(Saml2MessageBinding.from(SINGLE_SIGNON_BINDING))
				.singleLogoutServiceLocation(SINGLE_LOGOUT_URL)
				.singleLogoutServiceResponseLocation(SINGLE_LOGOUT_RESPONSE_URL)
				.singleLogoutServiceBinding(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING))
				.build();

		repository.save(updatedMetadata);
		AssertingPartyMetadata found = repository.findByEntityId(ENTITY_ID);

		assertThat(found).isNotNull();
		assertThat(found.getSingleSignOnServiceLocation()).isEqualTo("https://localhost/SSO/updated");
	}

	@Test
	void deleteMetadata() {
		AssertingPartyMetadata metadata = assertingPartyMetadata();
		repository.save(metadata);

		repository.delete(ENTITY_ID);

		AssertingPartyMetadata found = repository.findByEntityId(ENTITY_ID);
		assertThat(found).isNull();
	}

	@Test
	void findByEntityIdWhenNotExists() {
		AssertingPartyMetadata found = repository.findByEntityId("non-existent-entity-id");

		assertThat(found).isNull();
	}

	@Test
	void saveMultipleMetadataEntries() {
		AssertingPartyMetadata metadata1 = assertingPartyMetadata();

		AssertingPartyMetadata metadata2 = new RelyingPartyRegistration.AssertingPartyDetails.Builder()
				.entityId("https://idp2.example.org")
				.wantAuthnRequestsSigned(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST))
				.signingAlgorithms(signingAlgorithms -> signingAlgorithms.addAll(SIGNING_ALGORITHMS))
				.verificationX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.encryptionX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.singleSignOnServiceLocation("https://idp2.example.org/SSO")
				.singleSignOnServiceBinding(Saml2MessageBinding.from(SINGLE_SIGNON_BINDING))
				.singleLogoutServiceLocation("https://idp2.example.org/SLO")
				.singleLogoutServiceResponseLocation("https://idp2.example.org/SLO/response")
				.singleLogoutServiceBinding(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING))
				.build();

		repository.save(metadata1);
		repository.save(metadata2);

		AssertingPartyMetadata found1 = repository.findByEntityId(ENTITY_ID);
		AssertingPartyMetadata found2 = repository.findByEntityId("https://idp2.example.org");

		assertThat(found1).isNotNull();
		assertThat(found1.getEntityId()).isEqualTo(ENTITY_ID);

		assertThat(found2).isNotNull();
		assertThat(found2.getEntityId()).isEqualTo("https://idp2.example.org");
		assertThat(found2.getSingleSignOnServiceLocation()).isEqualTo("https://idp2.example.org/SSO");
	}

	@Test
	void iteratorReturnsAllMetadataEntries() {
		AssertingPartyMetadata metadata1 = assertingPartyMetadata();
		AssertingPartyMetadata metadata2 = new RelyingPartyRegistration.AssertingPartyDetails.Builder()
				.entityId("https://idp2.example.org")
				.wantAuthnRequestsSigned(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST))
				.signingAlgorithms(signingAlgorithms -> signingAlgorithms.addAll(SIGNING_ALGORITHMS))
				.verificationX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.encryptionX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.singleSignOnServiceLocation("https://idp2.example.org/SSO")
				.singleSignOnServiceBinding(Saml2MessageBinding.from(SINGLE_SIGNON_BINDING))
				.singleLogoutServiceLocation("https://idp2.example.org/SLO")
				.singleLogoutServiceResponseLocation("https://idp2.example.org/SLO/response")
				.singleLogoutServiceBinding(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING))
				.build();

		repository.save(metadata1);
		repository.save(metadata2);

		Iterator<AssertingPartyMetadata> iterator = repository.iterator();
		List<AssertingPartyMetadata> metadataList = new ArrayList<>();
		iterator.forEachRemaining(metadataList::add);
		assertThat(metadataList).hasSize(2);
		List<String> entityIds = metadataList.stream()
				.map(AssertingPartyMetadata::getEntityId)
				.collect(Collectors.toList());
		assertThat(entityIds).containsExactlyInAnyOrder(ENTITY_ID, "https://idp2.example.org");
	}

	private AssertingPartyMetadata assertingPartyMetadata() {
		return new RelyingPartyRegistration.AssertingPartyDetails.Builder()
				.entityId(ENTITY_ID)
				.wantAuthnRequestsSigned(Boolean.parseBoolean(SINGLE_SIGNON_SIGN_REQUEST))
				.signingAlgorithms(signingAlgorithms -> signingAlgorithms.addAll(SIGNING_ALGORITHMS))
				.verificationX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.encryptionX509Credentials(credentials -> credentials.add(asCredential(certificate)))
				.singleSignOnServiceLocation(SINGLE_SIGNON_URL)
				.singleSignOnServiceBinding(Saml2MessageBinding.from(SINGLE_SIGNON_BINDING))
				.singleLogoutServiceLocation(SINGLE_LOGOUT_URL)
				.singleLogoutServiceResponseLocation(SINGLE_LOGOUT_RESPONSE_URL)
				.singleLogoutServiceBinding(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING))
				.build();
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

	private Saml2X509Credential asCredential(X509Certificate certificate) {
		return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
				Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
	}
}
