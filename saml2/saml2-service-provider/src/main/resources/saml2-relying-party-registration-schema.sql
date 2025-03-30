CREATE TABLE saml2_relying_party_registration
(
    id                                       VARCHAR(255),
    entity_id                                VARCHAR(255),
    name_id_format                           VARCHAR(255),
    acs_location                             VARCHAR(255),
    acs_binding                              VARCHAR(255),
    signing_credentials                      blob,
    decryption_credentials                   blob,
    singlelogout_url                         VARCHAR(255),
    singlelogout_response_url                VARCHAR(255),
    singlelogout_binding                     VARCHAR(255),
    assertingparty_entity_id                 VARCHAR(255),
    assertingparty_metadata_uri              VARCHAR(255),
    assertingparty_singlesignon_url          VARCHAR(255),
    assertingparty_singlesignon_binding      VARCHAR(255),
    assertingparty_singlesignon_sign_request VARCHAR(255),
    assertingparty_verification_credentials  blob,
    assertingparty_singlelogout_url          VARCHAR(255),
    assertingparty_singlelogout_response_url VARCHAR(255),
    assertingparty_singlelogout_binding      VARCHAR(255),
    PRIMARY KEY (id)
);
