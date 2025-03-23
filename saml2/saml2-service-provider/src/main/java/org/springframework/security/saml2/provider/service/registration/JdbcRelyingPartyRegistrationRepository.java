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

import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.saml2.provider.service.registration.IterableRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
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
	 * @param jdbcOperations the JDBC operations
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public JdbcRelyingPartyRegistrationRepository(JdbcOperations jdbcOperations) {
		this(jdbcOperations, new DefaultLobHandler());
	}

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizedClientService} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param lobHandler the handler for large binary fields and large text fields
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
	 * @param authorizedClientRowMapper the {@link RowMapper} used for mapping the current
	 * row in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}
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
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, registrationId) };
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

		public final void setLobHandler(LobHandler lobHandler) {
			Assert.notNull(lobHandler, "lobHandler cannot be null");
			this.lobHandler = lobHandler;
		}

		@Override
		public RelyingPartyRegistration mapRow(ResultSet rs, int rowNum) throws SQLException {

			return new OAuth2AuthorizedClient(clientRegistration, principalName, accessToken, refreshToken);
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
