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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.log.LogMessage;
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
 * A JDBC implementation of {@link AssertingPartyMetadataRepository}.
 *
 * @author Cathy Wang
 * @since 7.0
 */
public final class JdbcAssertingPartyMetadataRepository implements AssertingPartyMetadataRepository {

	private final JdbcOperations jdbcOperations;

	private RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper =
			new AssertingPartyMetadataRowMapper(ResultSet::getBytes);

	private Function<AssertingPartyMetadata, List<SqlParameterValue>> assertingPartyMetadataParametersMapper =
			new AssertingPartyMetadataParametersMapper();

	private final SetBytes setBytes = PreparedStatement::setBytes;

	// @formatter:off
	static final String COLUMN_NAMES = "entity_id, "
			+ "metadata_uri, "
			+ "singlesignon_url, "
			+ "singlesignon_binding, "
			+ "singlesignon_sign_request, "
			+ "signing_algorithms, "
			+ "verification_credentials, "
			+ "encryption_credentials, "
			+ "singlelogout_url, "
			+ "singlelogout_response_url, "
			+ "singlelogout_binding";
	// @formatter:on

	private static final String TABLE_NAME = "saml2_asserting_party_metadata";

	private static final String ENTITY_ID_FILTER = "entity_id = ?";

	// @formatter:off
	private static final String LOAD_BY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ENTITY_ID_FILTER;

	private static final String LOAD_ALL_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME;

	protected static final String SAVE_SQL = "INSERT INTO " + TABLE_NAME + " ("
			+ COLUMN_NAMES
			+ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	private static final String DELETE_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + ENTITY_ID_FILTER;

	// @formatter:off
	private static final String UPDATE_SQL = "UPDATE " + TABLE_NAME
			+ " SET singlesignon_url = ?, " +
			"singlesignon_binding = ?, " +
			"singlesignon_sign_request = ?, " +
			"signing_algorithms = ?, " +
			"verification_credentials = ?, " +
			"encryption_credentials = ?, " +
			"singlelogout_url = ? ," +
			"singlelogout_response_url = ?, " +
			"singlelogout_binding = ?"
			+ " WHERE " + ENTITY_ID_FILTER;
	// @formatter:on

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 *
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcAssertingPartyMetadataRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}. The default is
	 * {@link AssertingPartyMetadataRowMapper}.
	 *
	 * @param assertingPartyMetadataRowMapper the {@link RowMapper} used for mapping the
	 *                                        current row in {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}
	 */
	public void setAssertingPartyMetadataRowMapper(
			RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper) {
		Assert.notNull(assertingPartyMetadataRowMapper, "assertingPartyMetadataRowMapper cannot be null");
		this.assertingPartyMetadataRowMapper = assertingPartyMetadataRowMapper;
	}

	public void setAssertingPartyMetadataParametersMapper(Function<AssertingPartyMetadata, List<SqlParameterValue>> assertingPartyMetadataParametersMapper) {
		Assert.notNull(assertingPartyMetadataParametersMapper, "assertingPartyMetadataParametersMapper cannot be null");
		this.assertingPartyMetadataParametersMapper = assertingPartyMetadataParametersMapper;
	}

	public void save(AssertingPartyMetadata metadata) {
		Assert.notNull(metadata, "metadata cannot be null");
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
		SqlParameterValue[] parameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.VARCHAR, entityId),};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(DELETE_SQL, pss);
	}

	@Override
	public AssertingPartyMetadata findByEntityId(String entityId) {
		Assert.hasText(entityId, "entityId cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.VARCHAR, entityId)};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<AssertingPartyMetadata> result = this.jdbcOperations.query(LOAD_BY_ID_SQL, pss,
				this.assertingPartyMetadataRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public Iterator<AssertingPartyMetadata> iterator() {
		List<AssertingPartyMetadata> result = this.jdbcOperations.query(LOAD_ALL_SQL,
				this.assertingPartyMetadataRowMapper);
		return result.iterator();
	}

	private static class AssertingPartyMetadataParametersMapper
			implements Function<AssertingPartyMetadata, List<SqlParameterValue>> {

		private final Logger logger = LoggerFactory.getLogger(AssertingPartyMetadataParametersMapper.class);

		private final Serializer<Object> serializer = new DefaultSerializer();

		@Override
		public List<SqlParameterValue> apply(AssertingPartyMetadata record) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getEntityId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleSignOnServiceLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleSignOnServiceBinding().getUrn()));
			parameters.add(new SqlParameterValue(Types.BOOLEAN, record.getWantAuthnRequestsSigned()));
			try {
				parameters.add(new SqlParameterValue(Types.BLOB,
						this.serializer.serializeToByteArray(record.getSigningAlgorithms())));
			} catch (IOException ex) {
				this.logger.debug("Failed to serialize signing algorithms", ex);
				throw new IllegalArgumentException(ex);
			}
			try {
				parameters.add(new SqlParameterValue(Types.BLOB,
						this.serializer.serializeToByteArray(record.getVerificationX509Credentials())));
			} catch (IOException ex) {
				this.logger.debug("Failed to serialize verification credentials", ex);
				throw new IllegalArgumentException(ex);
			}
			try {
				parameters.add(new SqlParameterValue(Types.BLOB,
						this.serializer.serializeToByteArray(record.getEncryptionX509Credentials())));
			} catch (IOException ex) {
				this.logger.debug("Failed to serialize encryption credentials", ex);
				throw new IllegalArgumentException(ex);
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceResponseLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceBinding().getUrn()));
			return parameters;
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

		private final Log logger = LogFactory.getLog(AssertingPartyMetadataRowMapper.class);

		private final Deserializer<Object> deserializer = new DefaultDeserializer();

		private final GetBytes getBytes;

		AssertingPartyMetadataRowMapper(GetBytes getBytes) {
			this.getBytes = getBytes;
		}

		@Override
		public AssertingPartyMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
			String entityId = rs.getString("entity_id");
			if (entityId == null) {
				this.logger.debug("entityId can not be null");
				return null;
			}
			String metadataUri = rs.getString("metadata_uri");
			String singleSignOnUrl = rs.getString("singlesignon_url");
			Saml2MessageBinding singleSignOnBinding = Saml2MessageBinding.from(rs.getString("singlesignon_binding"));
			boolean singleSignOnSignRequest = rs.getBoolean("singlesignon_sign_request");
			String singleLogoutUrl = rs.getString("singlelogout_url");
			String singleLogoutResponseUrl = rs.getString("singlelogout_response_url");
			Saml2MessageBinding singleLogoutBinding = Saml2MessageBinding.from(rs.getString("singlelogout_binding"));
			byte[] signingAlgorithmsBytes = this.getBytes.getBytes(rs, "signing_algorithms");
			byte[] verificationCredentialsBytes = this.getBytes.getBytes(rs, "verification_credentials");
			byte[] encryptionCredentialsBytes = this.getBytes.getBytes(rs, "encryption_credentials");

			boolean usingMetadata = StringUtils.hasText(metadataUri);
			AssertingPartyMetadata.Builder<?> builder = (!usingMetadata) ? new AssertingPartyDetails.Builder().entityId(entityId)
					: createBuilderUsingMetadata(entityId, metadataUri);
			try {
				if (signingAlgorithmsBytes != null) {
					List<String> signingAlgorithms = (List<String>) deserializer.deserializeFromByteArray(signingAlgorithmsBytes);
					builder.signingAlgorithms(algorithms -> algorithms.addAll(signingAlgorithms));
				}
				if (verificationCredentialsBytes != null) {
					Collection<Saml2X509Credential> verificationCredentials = (Collection<Saml2X509Credential>) deserializer.deserializeFromByteArray(verificationCredentialsBytes);
					builder.verificationX509Credentials(credentials -> credentials.addAll(verificationCredentials));
				}
				if (encryptionCredentialsBytes != null) {
					Collection<Saml2X509Credential> encryptionCredentials = (Collection<Saml2X509Credential>) deserializer.deserializeFromByteArray(encryptionCredentialsBytes);
					builder.encryptionX509Credentials(credentials -> credentials.addAll(encryptionCredentials));
				}
			} catch (Exception ex) {
				this.logger.debug(
						LogMessage.format("Parsing serialized credentials for entity %s failed", entityId), ex);
				return null;
			}

			applyingWhenNonNull(singleSignOnUrl, builder::singleSignOnServiceLocation);
			applyingWhenNonNull(singleSignOnBinding, builder::singleSignOnServiceBinding);
			applyingWhenNonNull(singleSignOnSignRequest, builder::wantAuthnRequestsSigned);
			applyingWhenNonNull(singleLogoutUrl, builder::singleLogoutServiceLocation);
			applyingWhenNonNull(singleLogoutResponseUrl, builder::singleLogoutServiceResponseLocation);
			applyingWhenNonNull(singleLogoutBinding, builder::singleLogoutServiceBinding);
			return builder.build();
		}

		private <T> void applyingWhenNonNull(T value, Consumer<T> consumer) {
			if (value != null) {
				consumer.accept(value);
			}
		}

		private AssertingPartyMetadata.Builder<?> createBuilderUsingMetadata(String entityId, String metadataUri) {
			Collection<AssertingPartyMetadata.Builder<?>> candidates = AssertingPartyMetadata
					.collectionFromMetadataLocation(metadataUri);
			for (AssertingPartyMetadata.Builder<?> candidate : candidates) {
				if (entityId == null || entityId.equals(getEntityId(candidate))) {
					return candidate;
				}
			}
			throw new IllegalStateException("No asserting party metadata with Entity ID '" + entityId + "' found");
		}

		private Object getEntityId(AssertingPartyMetadata.Builder<?> candidate) {
			return candidate.build().getEntityId();
		}
	}

	private interface SetBytes {

		void setBytes(PreparedStatement ps, int index, byte[] bytes) throws SQLException;

	}

	private interface GetBytes {

		byte[] getBytes(ResultSet rs, String columnName) throws SQLException;

	}

}
