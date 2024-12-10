-- Drop tables if they exist in the reverse order of creation (to respect dependencies)
DROP TABLE IF EXISTS rsa_key_pairs CASCADE;
DROP TABLE IF EXISTS oauth2_authorization CASCADE;
DROP TABLE IF EXISTS oauth2_authorization_consent CASCADE;
DROP TABLE IF EXISTS oauth2_registered_client CASCADE;
DROP TABLE IF EXISTS authorities CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS userinfo CASCADE;
DROP TABLE IF EXISTS spring_session_attributes CASCADE;
DROP TABLE IF EXISTS spring_session CASCADE;

CREATE TABLE IF NOT EXISTS spring_session
(
    primary_id            CHARACTER(36) PRIMARY KEY NOT NULL,
    session_id            CHARACTER(36)             NOT NULL,
    creation_time         BIGINT                    NOT NULL,
    last_access_time      BIGINT                    NOT NULL,
    max_inactive_interval INTEGER                   NOT NULL,
    expiry_time           BIGINT                    NOT NULL,
    principal_name        CHARACTER VARYING(100)
);
CREATE UNIQUE INDEX IF NOT EXISTS spring_session_ix1 ON spring_session USING btree (session_id);
CREATE INDEX IF NOT EXISTS spring_session_ix2 ON spring_session USING btree (expiry_time);
CREATE INDEX IF NOT EXISTS spring_session_ix3 ON spring_session USING btree (principal_name);

-- session attributes
CREATE TABLE IF NOT EXISTS spring_session_attributes
(
    session_primary_id CHARACTER(36)          NOT NULL,
    attribute_name     CHARACTER VARYING(200) NOT NULL,
    attribute_bytes    bytea                  NOT NULL,
    PRIMARY KEY (session_primary_id, attribute_name),
    FOREIGN KEY (session_primary_id) REFERENCES spring_session (primary_id)
        MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE
);
--


CREATE TABLE IF NOT EXISTS users
(
    username VARCHAR(200) NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled  BOOLEAN      NOT NULL
);

CREATE TABLE userinfo
(
    id                    SERIAL PRIMARY KEY,
    username              VARCHAR(255) UNIQUE NOT NULL,
    full_name             VARCHAR(100),
    picture               VARCHAR(255),
    email                 VARCHAR(100),
    email_verified        BOOLEAN,
    gender                VARCHAR(50),
    birthdate             DATE,
    phone_number          VARCHAR(50),
    phone_number_verified BOOLEAN,
    address               VARCHAR(255),
    position              VARCHAR(255),
    department            VARCHAR(255),
    note                  TEXT,
    updated_at            TIMESTAMP,
    created_at            TIMESTAMP,
    CONSTRAINT fk_userinfo_users FOREIGN KEY (username) REFERENCES users (username)
);

CREATE TABLE IF NOT EXISTS authorities
(
    username  VARCHAR(200) NOT NULL,
    authority VARCHAR(256) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users (username),
    CONSTRAINT username_authority UNIQUE (username, authority)
);


CREATE TABLE IF NOT EXISTS oauth2_registered_client
(
    id                            VARCHAR(100)                            NOT NULL,
    client_id                     VARCHAR(100)                            NOT NULL,
    client_id_issued_at           TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 VARCHAR(200)  DEFAULT NULL,
    client_secret_expires_at      TIMESTAMP     DEFAULT NULL,
    client_name                   VARCHAR(200)                            NOT NULL,
    client_authentication_methods VARCHAR(1000)                           NOT NULL,
    authorization_grant_types     VARCHAR(1000)                           NOT NULL,
    redirect_uris                 VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris     VARCHAR(1000) DEFAULT NULL,
    scopes                        VARCHAR(1000)                           NOT NULL,
    client_settings               VARCHAR(2000)                           NOT NULL,
    token_settings                VARCHAR(2000)                           NOT NULL,
    PRIMARY KEY (id)
);



CREATE TABLE IF NOT EXISTS oauth2_authorization_consent
(
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name       VARCHAR(200)  NOT NULL,
    authorities          VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization
(
    id                            VARCHAR(100) NOT NULL,
    registered_client_id          VARCHAR(100) NOT NULL,
    principal_name                VARCHAR(200) NOT NULL,
    authorization_grant_type      VARCHAR(100) NOT NULL,
    authorized_scopes             VARCHAR(1000) DEFAULT NULL,
    attributes                    TEXT          DEFAULT NULL,
    state                         VARCHAR(500)  DEFAULT NULL,
    authorization_code_value      TEXT          DEFAULT NULL,
    authorization_code_issued_at  TIMESTAMP     DEFAULT NULL,
    authorization_code_expires_at TIMESTAMP     DEFAULT NULL,
    authorization_code_metadata   TEXT          DEFAULT NULL,
    access_token_value            TEXT          DEFAULT NULL,
    access_token_issued_at        TIMESTAMP     DEFAULT NULL,
    access_token_expires_at       TIMESTAMP     DEFAULT NULL,
    access_token_metadata         TEXT          DEFAULT NULL,
    access_token_type             VARCHAR(100)  DEFAULT NULL,
    access_token_scopes           VARCHAR(1000) DEFAULT NULL,
    oidc_id_token_value           TEXT          DEFAULT NULL,
    oidc_id_token_issued_at       TIMESTAMP     DEFAULT NULL,
    oidc_id_token_expires_at      TIMESTAMP     DEFAULT NULL,
    oidc_id_token_metadata        TEXT          DEFAULT NULL,
    refresh_token_value           TEXT          DEFAULT NULL,
    refresh_token_issued_at       TIMESTAMP     DEFAULT NULL,
    refresh_token_expires_at      TIMESTAMP     DEFAULT NULL,
    refresh_token_metadata        TEXT          DEFAULT NULL,
    user_code_value               TEXT          DEFAULT NULL,
    user_code_issued_at           TIMESTAMP     DEFAULT NULL,
    user_code_expires_at          TIMESTAMP     DEFAULT NULL,
    user_code_metadata            TEXT          DEFAULT NULL,
    device_code_value             TEXT          DEFAULT NULL,
    device_code_issued_at         TIMESTAMP     DEFAULT NULL,
    device_code_expires_at        TIMESTAMP     DEFAULT NULL,
    device_code_metadata          TEXT          DEFAULT NULL,
    PRIMARY KEY (id)
);



CREATE TABLE IF NOT EXISTS rsa_key_pairs
(
    id          VARCHAR(1000) NOT NULL PRIMARY KEY,
    private_key TEXT          NOT NULL,
    public_key  TEXT          NOT NULL,
    created     DATE          NOT NULL,
    UNIQUE (id, created)
);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

