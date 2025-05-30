CREATE TABLE saml2_asserting_party_metadata
(
    id                        VARCHAR(200) NOT NULL,
    entity_id                 VARCHAR(1000),
    metadata_uri              VARCHAR(1000),
    singlesignon_url          VARCHAR(1000),
    singlesignon_binding      VARCHAR(200),
    singlesignon_sign_request VARCHAR(1000),
    verification_credentials  blob,
    singlelogout_url          VARCHAR(1000),
    singlelogout_response_url VARCHAR(1000),
    singlelogout_binding      VARCHAR(200),
    PRIMARY KEY (id)
);
