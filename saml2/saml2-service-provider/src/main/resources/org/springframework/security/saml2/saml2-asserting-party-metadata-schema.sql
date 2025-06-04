CREATE TABLE saml2_asserting_party_metadata
(
    entity_id                 VARCHAR(1000) NOT NULL,
    metadata_uri              VARCHAR(1000),
    singlesignon_url          VARCHAR(1000),
    singlesignon_binding      VARCHAR(200),
    singlesignon_sign_request VARCHAR(1000),
    signing_algorithms        blob,
    verification_credentials  blob,
    encryption_credentials    blob,
    singlelogout_url          VARCHAR(1000),
    singlelogout_response_url VARCHAR(1000),
    singlelogout_binding      VARCHAR(200),
    PRIMARY KEY (entity_id)
);
