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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Registration;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import java.util.function.Consumer;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class JdbcRelyingPartyRegistrationRepository implements IterableRelyingPartyRegistrationRepository {

	// @formatter:off
	private static final String COLUMN_NAMES = "entity_id, "
			+ "name_id_format, "
			+ "acs_location, "
			+ "acs_binding, "
			+ "signing_credentials, "
			+ "decryption_credentials, "
			+ "singlelogout_url, "
			+ "singlelogout_response_url, "
			+ "singlelogout_binding, "
			+ "assertingparty_entity_id, "
			+ "assertingparty_metadata_uri, "
			+ "assertingparty_singlesignon_url, "
			+ "assertingparty_singlesignon_binding, "
			+ "assertingparty_singlesignon_sign_request, "
			+ "assertingparty_verification_credentials, "
			+ "assertingparty_singlelogout_url, "
			+ "assertingparty_singlelogout_response_url, "
			+ "assertingparty_singlelogout_binding"
		;
	// @formatter:on

	private static final String TABLE_NAME = "saml2_relying_party_registration";

	private static final String PK_FILTER = "entity_id = ?";

	// @formatter:off
	private static final String LOAD_RP_REGISTRATION_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	// @formatter:off
	private static final String SAVE_RP_REGISTRATION_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	// @formatter:off
	private static final String UPDATE_AUTHORIZED_CLIENT_SQL = "UPDATE " + TABLE_NAME
			+ " SET access_token_type = ?, access_token_value = ?, access_token_issued_at = ?,"
			+ " access_token_expires_at = ?, access_token_scopes = ?,"
			+ " refresh_token_value = ?, refresh_token_issued_at = ?"
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	protected final JdbcOperations jdbcOperations;

	protected RowMapper<RelyingPartyRegistration> authorizedClientRowMapper;

	protected final LobHandler lobHandler;

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizedClientService} using the provided
	 * parameters.
	 *
	 * @param jdbcOperations               the JDBC operations
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public JdbcRelyingPartyRegistrationRepository(JdbcOperations jdbcOperations) {
		this(jdbcOperations, new DefaultLobHandler());
	}

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizedClientService} using the provided
	 * parameters.
	 *
	 * @param jdbcOperations               the JDBC operations
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param lobHandler                   the handler for large binary fields and large text fields
	 * @since 5.5
	 */
	public JdbcRelyingPartyRegistrationRepository(JdbcOperations jdbcOperations,
			LobHandler lobHandler) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(lobHandler, "lobHandler cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.lobHandler = lobHandler;
		OAuth2AuthorizedClientRowMapper authorizedClientRowMapper = new OAuth2AuthorizedClientRowMapper();
		authorizedClientRowMapper.setLobHandler(lobHandler);
		this.authorizedClientRowMapper = authorizedClientRowMapper;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}. The default is
	 * {@link OAuth2AuthorizedClientRowMapper}.
	 *
	 * @param authorizedClientRowMapper the {@link RowMapper} used for mapping the current
	 *                                  row in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}
	 */
	public final void setAuthorizedClientRowMapper(RowMapper<RelyingPartyRegistration> authorizedClientRowMapper) {
		Assert.notNull(authorizedClientRowMapper, "authorizedClientRowMapper cannot be null");
		this.authorizedClientRowMapper = authorizedClientRowMapper;
	}

	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		return null;
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.VARCHAR, registrationId)};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<RelyingPartyRegistration> result = this.jdbcOperations.query(LOAD_RP_REGISTRATION_SQL, pss,
				this.authorizedClientRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}.
	 */
	public static class OAuth2AuthorizedClientRowMapper implements RowMapper<RelyingPartyRegistration> {

		protected LobHandler lobHandler = new DefaultLobHandler();

		private ObjectMapper objectMapper = new ObjectMapper();

		public final void setLobHandler(LobHandler lobHandler) {
			Assert.notNull(lobHandler, "lobHandler cannot be null");
			this.lobHandler = lobHandler;
		}

		@Override
		public RelyingPartyRegistration mapRow(ResultSet rs, int rowNum) throws SQLException {
			String id = rs.getString("id");
			String entityId = rs.getString("entity_id");
			String nameIdFormat = rs.getString("name_id_format");
			String acsLocation = rs.getString("acs_location");
			String acsBinding = rs.getString("acs_binding");
			Credentials signingCredentials = parseCredentials(getLobValue(rs, "signing_credentials"));
			Credentials decryptionCredentials = parseCredentials(getLobValue(rs, "decryption_credentials"));
			String singleLogoutUrl = rs.getString("singlelogout_url");
			String singleLogoutResponseUrl = rs.getString("singlelogout_response_url");
			String singleLogoutBinding = rs.getString("singlelogout_binding");
			String assertingPartyEntityId = rs.getString("assertingparty_entity_id");
			String assertingPartyMetadataUri = rs.getString("assertingparty_metadata_uri");
			String assertingPartySingleSignOnUrl = rs.getString("assertingparty_singlesignon_url");
			Saml2MessageBinding assertingPartySingleSignOnBinding = Saml2MessageBinding.valueOf(rs.getString("assertingparty_singlesignon_binding"));
			Boolean assertingPartySingleSignOnSignRequest = rs.getBoolean("assertingparty_singlesignon_sign_request");
			Credentials assertingPartyVerificationCredentials = parseCredentials(getLobValue(rs, "assertingparty_verification_credentials"));
			String assertingPartySingleLogoutUrl = rs.getString("assertingparty_singlelogout_url");
			String assertingPartySingleLogoutResponseUrl = rs.getString("assertingparty_singlelogout_response_url");
			Saml2MessageBinding assertingPartySingleLogoutBinding = Saml2MessageBinding.valueOf(rs.getString("assertingparty_singlelogout_binding"));

			boolean usingMetadata = StringUtils.hasText(assertingPartyMetadataUri);
			RelyingPartyRegistration.Builder builder = (!usingMetadata) ? RelyingPartyRegistration.withRegistrationId(id)
					: createBuilderUsingMetadata(assertingPartyEntityId, assertingPartyMetadataUri).registrationId(id);
			builder.assertionConsumerServiceLocation(acsLocation);
			builder.assertionConsumerServiceBinding(Saml2MessageBinding.valueOf(acsBinding));
			builder.assertingPartyMetadata(mapAssertingParty(assertingPartyEntityId, assertingPartySingleSignOnBinding, assertingPartySingleSignOnUrl, assertingPartySingleSignOnSignRequest,
					assertingPartySingleLogoutBinding, assertingPartySingleLogoutResponseUrl, assertingPartySingleLogoutUrl));
			builder.signingX509Credentials((credentials) -> signingCredentials
					.getCredentials()
					.stream()
					.map(this::asSigningCredential)
					.forEach(credentials::add));
			builder.decryptionX509Credentials((credentials) -> properties.getDecryption()
					.getCredentials()
					.stream()
					.map(this::asDecryptionCredential)
					.forEach(credentials::add));
			builder.assertingPartyMetadata(
					(details) -> details.verificationX509Credentials((credentials) -> properties.getAssertingparty()
							.getVerification()
							.getCredentials()
							.stream()
							.map(this::asVerificationCredential)
							.forEach(credentials::add)));
			builder.singleLogoutServiceLocation(properties.getSinglelogout().getUrl());
			builder.singleLogoutServiceResponseLocation(properties.getSinglelogout().getResponseUrl());
			builder.singleLogoutServiceBinding(properties.getSinglelogout().getBinding());
			builder.entityId(properties.getEntityId());
			builder.nameIdFormat(properties.getNameIdFormat());
			RelyingPartyRegistration registration = builder.build();
			boolean signRequest = registration.getAssertingPartyMetadata().getWantAuthnRequestsSigned();
			validateSigningCredentials(properties, signRequest);
			return registration;
		}

		private Saml2X509Credential asSigningCredential(Signing.Credential properties) {
			RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
			X509Certificate certificate = readCertificate(properties.getCertificateLocation());
			return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
		}

		private RSAPrivateKey readPrivateKey(Resource location) {
			Assert.state(location != null, "No private key location specified");
			Assert.state(location.exists(), () -> "Private key location '" + location + "' does not exist");
			try (InputStream inputStream = location.getInputStream()) {
				PemContent pemContent = PemContent.load(inputStream);
				PrivateKey privateKey = pemContent.getPrivateKey();
				Assert.isInstanceOf(RSAPrivateKey.class, privateKey,
						"PrivateKey in resource '" + location + "' must be an RSAPrivateKey");
				return (RSAPrivateKey) privateKey;
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex);
			}
		}

		private X509Certificate readCertificate(Resource location) {
			Assert.state(location != null, "No certificate location specified");
			Assert.state(location.exists(), () -> "Certificate  location '" + location + "' does not exist");
			try (InputStream inputStream = location.getInputStream()) {
				PemContent pemContent = PemContent.load(inputStream);
				List<X509Certificate> certificates = pemContent.getCertificates();
				return certificates.get(0);
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex);
			}
		}

		private Consumer<AssertingPartyMetadata.Builder<?>> mapAssertingParty(String assertingPartyEntityId, Saml2MessageBinding assertingPartySingleSignOnBinding, String assertingPartySingleSignOnUrl,
				Boolean assertingPartySingleSignOnSignRequest, Saml2MessageBinding assertingPartySingleLogoutBinding, String assertingPartySingleLogoutResponseUrl, String assertingPartySingleLogoutUrl) {
			return (details) -> {
				details.entityId(assertingPartyEntityId);
				details.singleSignOnServiceBinding(assertingPartySingleSignOnBinding);
				details.singleSignOnServiceLocation(assertingPartySingleSignOnUrl);
				details.wantAuthnRequestsSigned(assertingPartySingleSignOnSignRequest);
				details.singleLogoutServiceLocation(assertingPartySingleLogoutUrl);
				details.singleLogoutServiceResponseLocation(assertingPartySingleLogoutResponseUrl);
				details.singleLogoutServiceBinding(assertingPartySingleLogoutBinding);
			};
		}

		private RelyingPartyRegistration.Builder createBuilderUsingMetadata(String assertingPartyEntityId, String assertingPartyMetadataUri) {
			Collection<RelyingPartyRegistration.Builder> candidates = RelyingPartyRegistrations
					.collectionFromMetadataLocation(assertingPartyMetadataUri);
			for (RelyingPartyRegistration.Builder candidate : candidates) {
				if (assertingPartyEntityId == null || assertingPartyEntityId.equals(getEntityId(candidate))) {
					return candidate;
				}
			}
			throw new IllegalStateException("No relying party with Entity ID '" + assertingPartyEntityId + "' found");
		}

		private Credentials parseCredentials(String signingCredentials) {
			try {
				return this.objectMapper.readValue(signingCredentials, new TypeReference<>() {
				});
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex.getMessage(), ex);
			}
		}

		private String getLobValue(ResultSet rs, String columnName) throws SQLException {
			String columnValue = null;
			byte[] columnValueBytes = this.lobHandler.getBlobAsBytes(rs, columnName);
			if (columnValueBytes != null) {
				columnValue = new String(columnValueBytes, StandardCharsets.UTF_8);
			}
			return columnValue;
		}

		public static class Credentials {

			/**
			 * Credentials used for signing the SAML authentication request.
			 */
			private List<Credential> credentials = new ArrayList<>();

			public List<Credential> getCredentials() {
				return this.credentials;
			}

			public void setCredentials(List<Credential> credentials) {
				this.credentials = credentials;
			}

			public static class Credential {

				/**
				 * Private key used for signing.
				 */
				private String privateKey;

				/**
				 * Relying Party X509Certificate shared with the identity provider.
				 */
				private String certificate;

				public String getPrivateKey() {
					return privateKey;
				}

				public void setPrivateKey(String privateKey) {
					this.privateKey = privateKey;
				}

				public String getCertificate() {
					return certificate;
				}

				public void setCertificate(String certificate) {
					this.certificate = certificate;
				}
			}

		}

		private Object getEntityId(RelyingPartyRegistration.Builder candidate) {
			String[] result = new String[1];
			candidate.assertingPartyMetadata((builder) -> result[0] = builder.build().getEntityId());
			return result[0];
		}



		private RelyingPartyRegistration asRegistration(String id, Registration properties) {

		}

	}

	private static final class LobCreatorArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {

		protected final LobCreator lobCreator;

		private LobCreatorArgumentPreparedStatementSetter(LobCreator lobCreator, Object[] args) {
			super(args);
			this.lobCreator = lobCreator;
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
					this.lobCreator.setBlobAsBytes(ps, parameterPosition, valueBytes);
					return;
				}
			}
			super.doSetValue(ps, parameterPosition, argValue);
		}

	}

}
