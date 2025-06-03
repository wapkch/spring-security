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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cryptacular.util.KeyPairUtil;
import org.opensaml.security.x509.X509Support;
import org.springframework.core.serializer.DefaultDeserializer;
import org.springframework.core.serializer.DefaultSerializer;
import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A JDBC implementation of AssertingPartyMetadataRepository.
 *
 * @since 7.0
 * @author Cathy Wang
 */
public final class JdbcAssertingPartyMetadataRepository {

	private Function<AssertingPartyMetadata, List<SqlParameterValue>> assertingPartyMetadataParametersMapper = new AssertingPartyMetadataParametersMapper();

	private SetBytes setBytes = PreparedStatement::setBytes;

	// @formatter:off
	static final String COLUMN_NAMES = "entity_id, "
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
			+ " WHERE " + ENTITY_ID_FILTER;

	private static final String SAVE_SQL = "INSERT INTO " + TABLE_NAME + " ("
			+ COLUMN_NAMES
			+ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	private static final String DELETE_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + ENTITY_ID_FILTER;

	// @formatter:off
	private static final String UPDATE_SQL = "UPDATE " + TABLE_NAME
			+ " SET singlesignon_url = ?, " +
			"singlesignon_binding = ?, " +
			"singlesignon_sign_request = ?, " +
			"verification_credentials = ?, " +
			"singlelogout_url = ? ," +
			"singlelogout_response_url = ?, " +
			"singlelogout_binding = ?"
			+ " WHERE " + ENTITY_ID_FILTER;
	// @formatter:on

	protected final JdbcOperations jdbcOperations;

	protected RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper;

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcAssertingPartyMetadataRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.assertingPartyMetadataRowMapper = new AssertingPartyMetadataRowMapper(ResultSet::getBytes);
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

	public void save(AssertingPartyMetadata metadata) {
		Assert.notNull(metadata, "AssertingPartyMetadata cannot be null");
		int rows = update(metadata);
		if (rows == 0) {
			insert(metadata);
		}
	}

	private void insert(AssertingPartyMetadata metadata) {
		List<SqlParameterValue> parameters = this.assertingPartyMetadataParametersMapper.apply(metadata);
		PreparedStatementSetter pss = new BlobArgumentPreparedStatementSetter(this.setBytes, parameters.toArray());
		this.jdbcOperations.update(SAVE_SQL, pss);
	}

	private int update(AssertingPartyMetadata metadata) {
		List<SqlParameterValue> parameters = this.assertingPartyMetadataParametersMapper.apply(metadata);
		SqlParameterValue credentialId = parameters.remove(0);
		parameters.add(credentialId);
		PreparedStatementSetter pss = new BlobArgumentPreparedStatementSetter(this.setBytes, parameters.toArray());
		return this.jdbcOperations.update(UPDATE_SQL, pss);
	}

	public void delete(String entityId) {
		Assert.notNull(entityId, "entityId cannot be null");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, entityId), };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(DELETE_SQL, pss);
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

	private static class AssertingPartyMetadataParametersMapper
			implements Function<AssertingPartyMetadata, List<SqlParameterValue>> {

		private final Serializer<Object> serializer = new DefaultSerializer();

		@Override
		public List<SqlParameterValue> apply(AssertingPartyMetadata record) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getEntityId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleSignOnServiceLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleSignOnServiceBinding()));
			parameters.add(new SqlParameterValue(Types.BOOLEAN, record.getWantAuthnRequestsSigned()));
			try {
				parameters.add(new SqlParameterValue(Types.BLOB,
						this.serializer.serializeToByteArray(record.getVerificationX509Credentials())));
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceResponseLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceBinding()));
			return parameters;
		}

		private Timestamp fromInstant(Instant instant) {
			if (instant == null) {
				return null;
			}
			return Timestamp.from(instant);
		}

	}

	private static final class BlobArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {

		private final SetBytes setBytes;

		private BlobArgumentPreparedStatementSetter(SetBytes setBytes, Object[] args) {
			super(args);
			this.setBytes = setBytes;
		}

		@Override
		protected void doSetValue(PreparedStatement ps, int parameterPosition, Object argValue) throws SQLException {
			if (argValue instanceof SqlParameterValue paramValue) {
				if (paramValue.getSqlType() == Types.BLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(byte[].class, paramValue.getValue(),
								"Value of blob parameter must be byte[]");
					}
					byte[] valueBytes = (byte[]) paramValue.getValue();
					this.setBytes.setBytes(ps, parameterPosition, valueBytes);
					return;
				}
			}
			super.doSetValue(ps, parameterPosition, argValue);
		}

	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}.
	 */
	private final static class AssertingPartyMetadataRowMapper implements RowMapper<AssertingPartyMetadata> {

		private final Log logger = LogFactory.getLog(getClass());


		private Deserializer<Object> deserializer = new DefaultDeserializer();

		private final GetBytes getBytes;

		AssertingPartyMetadataRowMapper(GetBytes getBytes) {
			this.getBytes = getBytes;
		}

		@Override
		public AssertingPartyMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
//			String registrationId = rs.getString("id");
			String entityId = rs.getString("entity_id");
			String metadataUri = null;
//			String metadataUri = rs.getString("metadata_uri");
			String singleSignOnUrl = rs.getString("singlesignon_url");
			Saml2MessageBinding singleSignOnBinding = Saml2MessageBinding
				.from(rs.getString("singlesignon_binding"));
			boolean singleSignOnSignRequest = rs.getBoolean("singlesignon_sign_request");
			Collection<Saml2X509Credential> verificationCredentials;
			try {
				verificationCredentials = (Collection<Saml2X509Credential>) deserializer.deserializeFromByteArray(
						this.getBytes.getBytes(rs, "verification_credentials"));
			}
			catch (IOException ex) {
//				this.logger.debug(
//						LogMessage.format("Verification certificate of %s could not be parsed.", registrationId), ex);
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
			builder.verificationX509Credentials(credentials -> credentials.addAll(verificationCredentials));
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

		private Saml2X509Credential asVerificationCredential(String certificate) throws Exception {
			X509Certificate x509Certificate = readCertificate(certificate);
			return new Saml2X509Credential(x509Certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
					Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
		}

		private RSAPrivateKey readPrivateKey(String privateKey) {
			return (RSAPrivateKey) KeyPairUtil.decodePrivateKey(privateKey.getBytes(StandardCharsets.UTF_8));
		}

		private X509Certificate readCertificate(String certificate) throws CertificateException {
			return X509Support.decodeCertificate(certificate);
		}

	}

	private interface SetBytes {

		void setBytes(PreparedStatement ps, int index, byte[] bytes) throws SQLException;

	}

	private interface GetBytes {

		byte[] getBytes(ResultSet rs, String columnName) throws SQLException;

	}

}
