
CREATE TABLE refresh_token
(
    id    INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    jti  UUID UNIQUE NOT NULL,
    token TEXT        NOT NULL,
    exp TIMESTAMP NOT NULL
);

DO
$$
    BEGIN
        RAISE NOTICE 'surface_type exists, skipping...';
    END
$$;
