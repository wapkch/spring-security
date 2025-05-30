/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.provider.service.registration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cryptacular.util.KeyPairUtil;
import org.opensaml.security.x509.X509Support;
import org.springframework.core.log.LogMessage;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A JDBC implementation of AssertingPartyMetadataRepository.
 *
 * @since 7.0
 * @author wangchao
 */
public final class JdbcAssertingPartyMetadataRepository {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	// @formatter:off
	static final String COLUMN_NAMES = "id, "
			+ "entity_id, "
			+ "metadata_uri, "
			+ "singlesignon_url, "
			+ "singlesignon_binding, "
			+ "singlesignon_sign_request, "
			+ "verification_credentials, "
			+ "singlelogout_url, "
			+ "singlelogout_response_url, "
			+ "singlelogout_binding";
	// @formatter:on

	private static final String TABLE_NAME = "saml2_asserting_party_metadata";

	private static final String PK_FILTER = "id = ?";

	private static final String ENTITY_ID_FILTER = "entity_id = ?";

	// @formatter:off
	private static final String LOAD_BY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + PK_FILTER;

	private static final String LOAD_BY_ENTITY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ENTITY_ID_FILTER;

	private static final String LOAD_ALL_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME;
	// @formatter:on

	protected final JdbcOperations jdbcOperations;

	protected RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper;

	protected final LobHandler lobHandler;

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcAssertingPartyMetadataRepository(JdbcOperations jdbcOperations) {
		this(jdbcOperations, new DefaultLobHandler());
	}

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 * @param lobHandler the handler for large binary fields and large text fields
	 */
	public JdbcAssertingPartyMetadataRepository(JdbcOperations jdbcOperations, LobHandler lobHandler) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(lobHandler, "lobHandler cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.lobHandler = lobHandler;
		AssertingPartyMetadataRowMapper rowMapper = new AssertingPartyMetadataRowMapper();
		rowMapper.setLobHandler(lobHandler);
		this.assertingPartyMetadataRowMapper = rowMapper;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}. The default is
	 * {@link AssertingPartyMetadataRowMapper}.
	 * @param assertingPartyMetadataRowMapper the {@link RowMapper} used for mapping the
	 * current row in {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}
	 */
	public void setAssertingPartyMetadataRowMapper(
			RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper) {
		Assert.notNull(assertingPartyMetadataRowMapper, "assertingPartyMetadataRowMapper cannot be null");
		this.assertingPartyMetadataRowMapper = assertingPartyMetadataRowMapper;
	}

	public AssertingPartyMetadata findUniqueByEntityId(String entityId) {
		Assert.hasText(entityId, "entityId cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, entityId) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<AssertingPartyMetadata> result = this.jdbcOperations.query(LOAD_BY_ID_SQL, pss,
				this.assertingPartyMetadataRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link RelyingPartyRegistration}.
	 */
	public static class AssertingPartyMetadataRowMapper implements RowMapper<AssertingPartyMetadata> {

		private final Log logger = LogFactory.getLog(getClass());

		protected LobHandler lobHandler = new DefaultLobHandler();

		public final void setLobHandler(LobHandler lobHandler) {
			Assert.notNull(lobHandler, "lobHandler cannot be null");
			this.lobHandler = lobHandler;
		}

		@Override
		public AssertingPartyMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
			String registrationId = rs.getString("id");
			String entityId = rs.getString("entity_id");
			String metadataUri = rs.getString("metadata_uri");
			String singleSignOnUrl = rs.getString("singlesignon_url");
			Saml2MessageBinding singleSignOnBinding = Saml2MessageBinding
				.from(rs.getString("singlesignon_binding"));
			boolean singleSignOnSignRequest = rs.getBoolean("singlesignon_sign_request");
			List<Certificate> verificationCredentials;
			try {
				verificationCredentials = parseCertificate(
						getLobValue(rs, "verification_credentials"));
			}
			catch (JsonProcessingException ex) {
				this.logger.error(
						LogMessage.format("Verification certificate of %s could not be parsed.", registrationId), ex);
				return null;
			}
			String singleLogoutUrl = rs.getString("singlelogout_url");
			String singleLogoutResponseUrl = rs.getString("singlelogout_response_url");
			Saml2MessageBinding singleLogoutBinding = Saml2MessageBinding
				.from(rs.getString("singlelogout_binding"));

			boolean usingMetadata = StringUtils.hasText(metadataUri);
			AssertingPartyMetadata.Builder<?> builder = (!usingMetadata)
					? new AssertingPartyDetails.Builder()
					: createBuilderUsingMetadata(entityId, metadataUri);
			builder.entityId(entityId);
			builder.wantAuthnRequestsSigned(singleSignOnSignRequest);

			List<Saml2X509Credential> saml2X509Credentials = new ArrayList<>();
			for (Certificate certificate : verificationCredentials) {
				try {
					saml2X509Credentials.add(asVerificationCredential(certificate));
				}
				catch (Exception ex) {
					this.logger.error(LogMessage.format("Verification credentials of %s must have a valid certificate.",
							registrationId), ex);
					return null;
				}
			}
			builder.verificationX509Credentials(credentials -> credentials.addAll(saml2X509Credentials));
			builder.singleSignOnServiceLocation(singleSignOnUrl);
			builder.singleSignOnServiceBinding(singleSignOnBinding);
			builder.singleLogoutServiceLocation(singleLogoutUrl);
			builder.singleLogoutServiceBinding(singleLogoutBinding);
			builder.singleLogoutServiceResponseLocation(singleLogoutResponseUrl);
			return builder.build();
		}

		private AssertingPartyMetadata.Builder<?> createBuilderUsingMetadata(String entityId, String metadataUri) {
			Collection<AssertingPartyMetadata.Builder<?>> candidates = AssertingPartyMetadata
					.collectionFromMetadataLocation(metadataUri);
			for (AssertingPartyMetadata.Builder<?> candidate : candidates) {
				if (entityId == null || entityId.equals(getEntityId(candidate))) {
					return candidate;
				}
			}
			throw new IllegalStateException("No relying party with Entity ID '" + entityId + "' found");
		}

		private Object getEntityId(AssertingPartyMetadata.Builder<?> candidate) {
			return candidate.build().getEntityId();
		}

		private Saml2X509Credential asVerificationCredential(Certificate certificate) throws Exception {
			X509Certificate x509Certificate = readCertificate(certificate.getCertificate());
			return new Saml2X509Credential(x509Certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
					Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
		}

		private RSAPrivateKey readPrivateKey(String privateKey) {
			return (RSAPrivateKey) KeyPairUtil.decodePrivateKey(privateKey.getBytes(StandardCharsets.UTF_8));
		}

		private X509Certificate readCertificate(String certificate) throws CertificateException {
			return X509Support.decodeCertificate(certificate);
		}

		private List<Credential> parseCredentials(String credentials) throws JsonProcessingException {
			if (!StringUtils.hasText(credentials)) {
				return new ArrayList<>();
			}
			return OBJECT_MAPPER.readValue(credentials, new TypeReference<>() {
			});
		}

		private List<Certificate> parseCertificate(String certificate) throws JsonProcessingException {
			if (!StringUtils.hasText(certificate)) {
				return new ArrayList<>();
			}
			return OBJECT_MAPPER.readValue(certificate, new TypeReference<>() {
			});
		}

		private String getLobValue(ResultSet rs, String columnName) throws SQLException {
			String columnValue = null;
			byte[] columnValueBytes = this.lobHandler.getBlobAsBytes(rs, columnName);
			if (columnValueBytes != null) {
				columnValue = new String(columnValueBytes, StandardCharsets.UTF_8);
			}
			return columnValue;
		}

	}

	public static class Certificate {

		private String certificate;

		public Certificate() {
		}

		public Certificate(String certificate) {
			this.certificate = certificate;
		}

		public String getCertificate() {
			return this.certificate;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

	}

	public static class Credential {

		private String privateKey;

		private String certificate;

		public Credential() {
		}

		public Credential(String privateKey, String certificate) {
			this.privateKey = privateKey;
			this.certificate = certificate;
		}

		public String getPrivateKey() {
			return this.privateKey;
		}

		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}

		public String getCertificate() {
			return this.certificate;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

	}

}
