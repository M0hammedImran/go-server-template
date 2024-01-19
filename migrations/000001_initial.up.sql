-- public.users definition
CREATE TABLE public.users (
    id bigserial NOT NULL,
    created_at timestamptz NULL,
    updated_at timestamptz NULL,
    deleted_at timestamptz NULL,
    first_name varchar(50) NULL,
    last_name varchar(50) NULL,
    email varchar(255) NOT NULL,
    "password" varchar(255) NOT NULL,
    "role" varchar(255) NOT NULL DEFAULT 'user'::character varying,
    "uuid" text NULL,
    otp text NULL,
    otp_expiry timestamptz NULL,
    CONSTRAINT users_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_users_deleted_at ON public.users USING btree (deleted_at);
CREATE UNIQUE INDEX idx_users_email ON public.users USING btree (email);
CREATE UNIQUE INDEX idx_users_uuid ON public.users USING btree (uuid);
-- public.auth_tokens definition
CREATE TABLE public.auth_tokens (
    id bigserial NOT NULL,
    created_at timestamptz NULL,
    updated_at timestamptz NULL,
    deleted_at timestamptz NULL,
    user_id int8 NULL,
    access_token text NULL,
    refresh_token text NULL,
    "uuid" text NULL,
    CONSTRAINT auth_tokens_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_auth_tokens_deleted_at ON public.auth_tokens USING btree (deleted_at);
CREATE UNIQUE INDEX idx_auth_tokens_uuid ON public.auth_tokens USING btree (uuid);
