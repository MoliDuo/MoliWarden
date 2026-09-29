--
-- PostgreSQL database dump
--



SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attachments (
    id text NOT NULL,
    cipher_id text NOT NULL,
    file_name text NOT NULL,
    size bigint NOT NULL,
    size_name text NOT NULL,
    key text
);


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id text NOT NULL,
    actor_user_id text,
    action text NOT NULL,
    category text DEFAULT 'system'::text NOT NULL,
    level text DEFAULT 'info'::text NOT NULL,
    target_type text,
    target_id text,
    metadata text,
    created_at text NOT NULL
);


--
-- Name: auth_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_requests (
    id text NOT NULL,
    user_id text NOT NULL,
    organization_id text,
    type bigint NOT NULL,
    request_device_identifier text NOT NULL,
    request_device_type bigint NOT NULL,
    request_ip_address text,
    request_country_name text,
    response_device_identifier text,
    access_code text NOT NULL,
    public_key text NOT NULL,
    key text,
    master_password_hash text,
    approved bigint,
    creation_date text NOT NULL,
    response_date text,
    authentication_date text
);


--
-- Name: cipher_collections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cipher_collections (
    cipher_id text NOT NULL,
    collection_id text NOT NULL
);


--
-- Name: cipher_user_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cipher_user_state (
    cipher_id text NOT NULL,
    user_id text NOT NULL,
    folder_id text,
    favorite bigint DEFAULT 0 NOT NULL,
    archived_at text
);


--
-- Name: ciphers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ciphers (
    id text NOT NULL,
    user_id text,
    organization_id text,
    type bigint NOT NULL,
    folder_id text,
    name text,
    notes text,
    favorite bigint DEFAULT 0 NOT NULL,
    data text NOT NULL,
    reprompt bigint,
    key text,
    created_at text NOT NULL,
    updated_at text NOT NULL,
    archived_at text,
    deleted_at text,
    CONSTRAINT ciphers_single_owner CHECK (((user_id IS NULL) <> (organization_id IS NULL)))
);


--
-- Name: collection_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collection_members (
    collection_id text NOT NULL,
    membership_id text NOT NULL,
    read_only bigint DEFAULT 0 NOT NULL,
    hide_passwords bigint DEFAULT 0 NOT NULL,
    manage bigint DEFAULT 0 NOT NULL
);


--
-- Name: collections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collections (
    id text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    external_id text,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.config (
    key text NOT NULL,
    value text NOT NULL
);


--
-- Name: devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.devices (
    user_id text NOT NULL,
    device_identifier text NOT NULL,
    name text NOT NULL,
    type bigint NOT NULL,
    session_stamp text,
    encrypted_user_key text,
    encrypted_public_key text,
    encrypted_private_key text,
    push_uuid text,
    push_token text,
    banned bigint DEFAULT 0 NOT NULL,
    banned_at text,
    device_note text,
    last_seen_at text,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: domain_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domain_settings (
    user_id text NOT NULL,
    equivalent_domains text DEFAULT '[]'::text NOT NULL,
    custom_equivalent_domains text DEFAULT '[]'::text NOT NULL,
    excluded_global_equivalent_domains text DEFAULT '[]'::text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: folders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.folders (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invites (
    code text NOT NULL,
    created_by text NOT NULL,
    used_by text,
    expires_at text NOT NULL,
    status text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: login_attempts_ip; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_attempts_ip (
    ip text NOT NULL,
    attempts bigint NOT NULL,
    locked_until bigint,
    updated_at bigint NOT NULL
);


--
-- Name: org_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_memberships (
    id text NOT NULL,
    org_id text NOT NULL,
    user_id text NOT NULL,
    status bigint NOT NULL,
    type bigint NOT NULL,
    access_all bigint DEFAULT 0 NOT NULL,
    akey text,
    revoked_status bigint,
    invited_by text,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id text NOT NULL,
    name text NOT NULL,
    billing_email text NOT NULL,
    public_key text,
    private_key text,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Name: rate_limit_buckets; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.rate_limit_buckets (
    bucket_key text NOT NULL,
    count bigint NOT NULL,
    expires_at bigint NOT NULL,
    updated_at bigint NOT NULL
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    token text NOT NULL,
    user_id text NOT NULL,
    expires_at bigint NOT NULL,
    device_identifier text,
    device_session_stamp text,
    security_stamp text,
    created_at bigint,
    last_used_at bigint,
    absolute_expires_at bigint,
    client_type text
);


--
-- Name: sends; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sends (
    id text NOT NULL,
    user_id text NOT NULL,
    type bigint NOT NULL,
    name text NOT NULL,
    notes text,
    data text NOT NULL,
    key text NOT NULL,
    password_hash text,
    password_salt text,
    password_iterations bigint,
    auth_type bigint DEFAULT 2 NOT NULL,
    emails text,
    max_access_count bigint,
    access_count bigint DEFAULT 0 NOT NULL,
    disabled bigint DEFAULT 0 NOT NULL,
    hide_email bigint,
    created_at text NOT NULL,
    updated_at text NOT NULL,
    expiration_date text,
    deletion_date text NOT NULL
);


--
-- Name: totp_login_replays; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_login_replays (
    user_id text NOT NULL,
    time_counter bigint NOT NULL,
    consumed_at bigint NOT NULL
);


--
-- Name: trusted_two_factor_device_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trusted_two_factor_device_tokens (
    token text NOT NULL,
    user_id text NOT NULL,
    device_identifier text NOT NULL,
    expires_at bigint NOT NULL
);


--
-- Name: used_attachment_download_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.used_attachment_download_tokens (
    jti text NOT NULL,
    expires_at bigint NOT NULL
);


--
-- Name: user_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_revisions (
    user_id text NOT NULL,
    revision_date text NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id text NOT NULL,
    email text NOT NULL,
    name text,
    master_password_hint text,
    master_password_hash text NOT NULL,
    key text NOT NULL,
    private_key text,
    public_key text,
    kdf_type bigint NOT NULL,
    kdf_iterations bigint NOT NULL,
    kdf_memory bigint,
    kdf_parallelism bigint,
    security_stamp text NOT NULL,
    role text DEFAULT 'user'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    verify_devices bigint DEFAULT 0 NOT NULL,
    totp_secret text,
    totp_recovery_code text,
    yubikey_key1 text,
    yubikey_key2 text,
    yubikey_key3 text,
    yubikey_key4 text,
    yubikey_key5 text,
    yubikey_nfc bigint DEFAULT 0 NOT NULL,
    api_key text,
    created_at text NOT NULL,
    updated_at text NOT NULL,
    key_id text
);


--
-- Name: webauthn_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_challenges (
    challenge_hash text NOT NULL,
    scope text NOT NULL,
    user_id text,
    expires_at bigint NOT NULL,
    used_at bigint,
    created_at bigint NOT NULL
);


--
-- Name: webauthn_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_credentials (
    id text NOT NULL,
    user_id text NOT NULL,
    purpose text DEFAULT 'login'::text NOT NULL,
    name text NOT NULL,
    public_key text NOT NULL,
    credential_id text NOT NULL,
    counter bigint DEFAULT 0 NOT NULL,
    type text,
    aa_guid text,
    transports text,
    encrypted_user_key text,
    encrypted_public_key text,
    encrypted_private_key text,
    supports_prf bigint DEFAULT 0 NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


--
-- Data for Name: attachments; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attachments (id, cipher_id, file_name, size, size_name, key) FROM stdin;
653ecd8b-ffab-41c6-9c3f-25c136c7acb6	5fe98dcb-b6a0-4238-a48d-eb35fa237f20	2.aXYtYXR0YWNobWVudC1uYW1lLWxvZ2luLXRleHQ=|Y3QtYXR0YWNobWVudC1uYW1lLWxvZ2luLXRleHQ=|bWFjLWF0dGFjaG1lbnQtbmFtZS1sb2dpbi10ZXh0	304	304 Bytes	2.aXYtYXR0YWNobWVudC1rZXktbG9naW4tdGV4dA==|Y3QtYXR0YWNobWVudC1rZXktbG9naW4tdGV4dA==|bWFjLWF0dGFjaG1lbnQta2V5LWxvZ2luLXRleHQ=
c16d244a-a288-424d-8f96-7681f442ba98	5fe98dcb-b6a0-4238-a48d-eb35fa237f20	2.aXYtYXR0YWNobWVudC1uYW1lLWxvZ2luLWJpbmFyeQ==|Y3QtYXR0YWNobWVudC1uYW1lLWxvZ2luLWJpbmFyeQ==|bWFjLWF0dGFjaG1lbnQtbmFtZS1sb2dpbi1iaW5hcnk=	512	512 Bytes	2.aXYtYXR0YWNobWVudC1rZXktbG9naW4tYmluYXJ5|Y3QtYXR0YWNobWVudC1rZXktbG9naW4tYmluYXJ5|bWFjLWF0dGFjaG1lbnQta2V5LWxvZ2luLWJpbmFyeQ==
bddd2745-23ec-4ea7-ab8e-173c052d27cf	620fe39b-4de1-4b3f-a180-00f8fb91f1bd	2.aXYtYXR0YWNobWVudC1uYW1lLW5vdGU=|Y3QtYXR0YWNobWVudC1uYW1lLW5vdGU=|bWFjLWF0dGFjaG1lbnQtbmFtZS1ub3Rl	31	31 Bytes	2.aXYtYXR0YWNobWVudC1rZXktbm90ZQ==|Y3QtYXR0YWNobWVudC1rZXktbm90ZQ==|bWFjLWF0dGFjaG1lbnQta2V5LW5vdGU=
7fa3a7a0-7c57-4b67-ae98-593607f4869f	16435347-0775-45fc-88af-c3b433258053	2.aXYtYXR0YWNobWVudC1uYW1lLW9yZy1jYXJk|Y3QtYXR0YWNobWVudC1uYW1lLW9yZy1jYXJk|bWFjLWF0dGFjaG1lbnQtbmFtZS1vcmctY2FyZA==	35	35 Bytes	2.aXYtYXR0YWNobWVudC1rZXktb3JnLWNhcmQ=|Y3QtYXR0YWNobWVudC1rZXktb3JnLWNhcmQ=|bWFjLWF0dGFjaG1lbnQta2V5LW9yZy1jYXJk
\.


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_logs (id, actor_user_id, action, category, level, target_type, target_id, metadata, created_at) FROM stdin;
01f6b961-8aeb-4e2e-a6ce-ff8416428be1	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	user.register.first_admin	security	security	user	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	{"email":"admin@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.2","userAgent":"node"}	2026-09-29T11:48:13.749Z
ae97f560-6f0f-4c7d-bc73-bb4923424573	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	auth.login.success	auth	info	user	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	{"grantType":"password","webSession":false,"deviceIdentifier":"90f4a140-2c18-42cd-8412-30e2c355befc","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:13.777Z
7f91cfa2-e10d-4e0c-97af-b91784c32603	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.794Z
995a627b-1f2e-40fe-a73c-8c134cc6276c	b47224e1-7541-4fed-8262-51a236e3f206	user.register.invite	security	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"email":"vault@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.3","userAgent":"node"}	2026-09-29T11:48:13.806Z
01a56f58-dd6a-4b3c-b24f-c4f51913d41e	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.821Z
163b7493-cd1b-4662-8d10-80da3842e5de	19290199-ab15-4919-823c-38b084e4e827	user.register.invite	security	info	user	19290199-ab15-4919-823c-38b084e4e827	{"email":"argon@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.4","userAgent":"node"}	2026-09-29T11:48:13.842Z
60876c3f-a82c-44e4-b5de-0b09e748f5b8	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.869Z
672e0338-e98d-4125-9bfc-9578a303fbae	f175fcfb-4094-43d5-9e98-b98725c0283a	user.register.invite	security	info	user	f175fcfb-4094-43d5-9e98-b98725c0283a	{"email":"totp@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.5","userAgent":"node"}	2026-09-29T11:48:13.909Z
49547ca3-500c-4d37-b278-ad3dc846c791	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.926Z
0bffdb1c-c723-4658-b092-bd13f73bcd35	d65ed8ce-595f-4e68-b9dc-9c54f036a177	user.register.invite	security	info	user	d65ed8ce-595f-4e68-b9dc-9c54f036a177	{"email":"yubikey@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.6","userAgent":"node"}	2026-09-29T11:48:13.938Z
c6f927cc-43cf-483d-a28f-53bbaa1eef6b	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.949Z
7416b9e0-5bf5-4830-9393-3fc12dcaa8c0	689390e4-7017-4751-b384-b34c8ef41116	user.register.invite	security	info	user	689390e4-7017-4751-b384-b34c8ef41116	{"email":"webauthn2fa@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.7","userAgent":"node"}	2026-09-29T11:48:13.961Z
4c9f68dc-51c7-44e8-9ab7-21eed629d799	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.971Z
0ea26992-2552-4119-98c8-302d515928cd	032772a9-e7c1-4305-a14e-2ed1b3fef953	user.register.invite	security	info	user	032772a9-e7c1-4305-a14e-2ed1b3fef953	{"email":"passkey@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.8","userAgent":"node"}	2026-09-29T11:48:13.982Z
875a2beb-1130-4276-8de2-1a4316c52a16	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:13.993Z
e31bfdc4-5911-44b5-9849-8520e81b2e99	9c97c610-d3f5-428b-b495-99d5d3a4d84c	user.register.invite	security	info	user	9c97c610-d3f5-428b-b495-99d5d3a4d84c	{"email":"manager@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.9","userAgent":"node"}	2026-09-29T11:48:14.004Z
d4590e76-4999-4e28-8250-18d7a315c859	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.018Z
cc7c7ba9-bfa0-4ff4-970c-e5037aefbc03	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	user.register.invite	security	info	user	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	{"email":"custom@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.10","userAgent":"node"}	2026-09-29T11:48:14.037Z
2b0253e7-86fe-4b1e-a5ca-a227202f0c0d	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.053Z
d5b6af4d-2e6c-4abe-a117-37e371abfff3	8ac1796d-04aa-41bd-a31b-cb96118b4703	user.register.invite	security	info	user	8ac1796d-04aa-41bd-a31b-cb96118b4703	{"email":"banned@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.11","userAgent":"node"}	2026-09-29T11:48:14.066Z
83cf1282-3b69-4ea9-a3f0-5617229733be	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.079Z
57d17daf-4345-4b4d-ba4d-1e0674b1f141	502e2390-384d-40f3-83b7-53bfc6ee882c	user.register.invite	security	info	user	502e2390-384d-40f3-83b7-53bfc6ee882c	{"email":"legacy-rawhash@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.12","userAgent":"node"}	2026-09-29T11:48:14.094Z
18a0e6d9-581c-4cff-9d46-66c8552eb1c1	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.110Z
ecc19484-3fe6-4acf-8afa-acd15fe6fff0	9fab75a7-a33b-412e-9dda-f934a392b545	user.register.invite	security	info	user	9fab75a7-a33b-412e-9dda-f934a392b545	{"email":"legacy-apikey@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.13","userAgent":"node"}	2026-09-29T11:48:14.135Z
3a380d24-4024-41d4-8f56-6800775c2773	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.148Z
315a0ce7-9618-4fe6-a2a9-273892703af4	2f27b21a-74ea-4b1c-b826-824b5ef88fb6	user.register.invite	security	info	user	2f27b21a-74ea-4b1c-b826-824b5ef88fb6	{"email":"legacy-domains@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.14","userAgent":"node"}	2026-09-29T11:48:14.163Z
08b51931-f1c7-4085-88fa-92edffdd9852	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.178Z
91fe434c-2933-4cfb-9c7a-e2e9f8cc6db8	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	user.register.invite	security	info	user	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	{"email":"legacy-totp@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.15","userAgent":"node"}	2026-09-29T11:48:14.190Z
6fbffbf5-7628-4a5a-910a-c8906215b403	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.200Z
ecc873e5-6a24-43d2-9583-b3e3f4e152ae	39af72eb-5f25-4b45-8504-2e4d6c39bccd	user.register.invite	security	info	user	39af72eb-5f25-4b45-8504-2e4d6c39bccd	{"email":"legacy-yubikey@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.16","userAgent":"node"}	2026-09-29T11:48:14.211Z
130523e0-c4a0-402b-835e-7fd2529b3c43	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.221Z
e1738f97-9d52-46b5-bf99-b0336f48c740	e730e934-1006-4550-a443-c12680cb0719	user.register.invite	security	info	user	e730e934-1006-4550-a443-c12680cb0719	{"email":"legacy-kdf@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.17","userAgent":"node"}	2026-09-29T11:48:14.232Z
44e3e2fb-9226-44bb-99f0-98a89ad44bd6	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.243Z
0663b8ce-67b0-4c6f-a422-0d38e3f2cd44	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	user.register.invite	security	info	user	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	{"email":"legacy-status@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.18","userAgent":"node"}	2026-09-29T11:48:14.254Z
e7c21f0a-7fdb-4933-935c-840966d019d5	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.266Z
ca0a1426-74fb-4097-96d2-f8e3945b6d34	d26f24e9-e3ad-4228-a191-c250c7423afd	user.register.invite	security	info	user	d26f24e9-e3ad-4228-a191-c250c7423afd	{"email":"legacy-session@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.19","userAgent":"node"}	2026-09-29T11:48:14.278Z
1dd29445-54e6-4882-b5f9-f718a3dfdd8d	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":24,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.291Z
64239890-4723-4426-88e6-bca3f24c0b05	1e7bbf40-54d5-49f3-812e-6336f876a0cd	user.register.invite	security	info	user	1e7bbf40-54d5-49f3-812e-6336f876a0cd	{"email":"legacy-cipher@fixture.example","method":"POST","path":"/api/accounts/register","ip":"10.77.0.20","userAgent":"node"}	2026-09-29T11:48:14.308Z
659c668f-678c-4d4e-a203-d54a0a7cafe3	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"password","webSession":false,"deviceIdentifier":"c51d72e8-0110-4bde-84b5-1938c8649ab7","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.323Z
038ca4d3-fad0-4056-a833-54c78485c3ad	19290199-ab15-4919-823c-38b084e4e827	auth.login.success	auth	info	user	19290199-ab15-4919-823c-38b084e4e827	{"grantType":"password","webSession":false,"deviceIdentifier":"c678062c-9a40-46ed-81d5-ddfa34f8be13","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.336Z
0ee49f13-8479-4170-9309-cb39355c9d6d	f175fcfb-4094-43d5-9e98-b98725c0283a	auth.login.success	auth	info	user	f175fcfb-4094-43d5-9e98-b98725c0283a	{"grantType":"password","webSession":false,"deviceIdentifier":"37c1227c-4767-4178-8052-1d23f3b6faf7","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.348Z
a737a07c-26c6-4215-831b-69eec052f730	d65ed8ce-595f-4e68-b9dc-9c54f036a177	auth.login.success	auth	info	user	d65ed8ce-595f-4e68-b9dc-9c54f036a177	{"grantType":"password","webSession":false,"deviceIdentifier":"a68f14aa-6f05-4b23-878d-23b68e79e4d7","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.360Z
8deb3ac9-fd86-473d-9603-5ba36853a2b2	689390e4-7017-4751-b384-b34c8ef41116	auth.login.success	auth	info	user	689390e4-7017-4751-b384-b34c8ef41116	{"grantType":"password","webSession":false,"deviceIdentifier":"86340e12-b069-4d87-8974-1f48770cf529","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.372Z
16a253f7-4a12-4680-a4fb-4373c2af4198	032772a9-e7c1-4305-a14e-2ed1b3fef953	auth.login.success	auth	info	user	032772a9-e7c1-4305-a14e-2ed1b3fef953	{"grantType":"password","webSession":false,"deviceIdentifier":"57183f3d-291b-4716-8d4e-e14e18c70c81","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.383Z
dca667f4-df97-49f5-86db-369756c00171	9c97c610-d3f5-428b-b495-99d5d3a4d84c	auth.login.success	auth	info	user	9c97c610-d3f5-428b-b495-99d5d3a4d84c	{"grantType":"password","webSession":false,"deviceIdentifier":"96b43e06-536e-46c9-8b56-84c5c0e2406b","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.394Z
cadf41f8-aa7d-4250-9a3e-53b05eb47517	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	auth.login.success	auth	info	user	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	{"grantType":"password","webSession":false,"deviceIdentifier":"40051e25-1a91-4de1-815d-3371a44f1a54","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.405Z
03791206-0ab8-4417-aee8-d6c7d86e4412	8ac1796d-04aa-41bd-a31b-cb96118b4703	auth.login.success	auth	info	user	8ac1796d-04aa-41bd-a31b-cb96118b4703	{"grantType":"password","webSession":false,"deviceIdentifier":"14de3d3f-e3f6-4649-89a0-b32e132e7e2c","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.416Z
b75cb709-516e-45d6-929c-7c93f402645e	502e2390-384d-40f3-83b7-53bfc6ee882c	auth.login.success	auth	info	user	502e2390-384d-40f3-83b7-53bfc6ee882c	{"grantType":"password","webSession":false,"deviceIdentifier":"5a09e91f-fc23-477f-8e5a-a05f346f905d","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.427Z
5e8bbd29-153b-4bab-b6f0-bcbb4413bcf2	9fab75a7-a33b-412e-9dda-f934a392b545	auth.login.success	auth	info	user	9fab75a7-a33b-412e-9dda-f934a392b545	{"grantType":"password","webSession":false,"deviceIdentifier":"4a506dd0-c5ac-4ba4-8748-ab39c7154af8","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.438Z
dd7ecfc8-918e-4172-94d7-15fe3f7d3e6c	2f27b21a-74ea-4b1c-b826-824b5ef88fb6	auth.login.success	auth	info	user	2f27b21a-74ea-4b1c-b826-824b5ef88fb6	{"grantType":"password","webSession":false,"deviceIdentifier":"ff8b4f9a-0fe2-4234-838d-49127e3c2cc9","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.449Z
2e13400f-f55c-43f6-be1b-e8d53e420978	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	auth.login.success	auth	info	user	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	{"grantType":"password","webSession":false,"deviceIdentifier":"474f8111-04de-451d-84e6-c71d61e157f2","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.461Z
576e6074-6fd7-49e0-a0fd-e9c9de76354c	39af72eb-5f25-4b45-8504-2e4d6c39bccd	auth.login.success	auth	info	user	39af72eb-5f25-4b45-8504-2e4d6c39bccd	{"grantType":"password","webSession":false,"deviceIdentifier":"1397c8e4-4edb-4f7e-89ed-a829f3e696f3","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.472Z
98e1c776-05a5-4c3f-a8dc-031361abc26c	e730e934-1006-4550-a443-c12680cb0719	auth.login.success	auth	info	user	e730e934-1006-4550-a443-c12680cb0719	{"grantType":"password","webSession":false,"deviceIdentifier":"a17a767e-6909-414a-8c39-7eff67e55c79","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.482Z
6e352cf6-f8b8-45cf-a693-86ec6414f305	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	auth.login.success	auth	info	user	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	{"grantType":"password","webSession":false,"deviceIdentifier":"a9214f0e-2628-4236-88d4-7e076a09b160","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.494Z
f0248a23-9fca-4615-aab4-6f855ecf1c09	d26f24e9-e3ad-4228-a191-c250c7423afd	auth.login.success	auth	info	user	d26f24e9-e3ad-4228-a191-c250c7423afd	{"grantType":"password","webSession":false,"deviceIdentifier":"14e2c52a-f0de-4ae5-81e7-d65826905eab","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.505Z
b02d7c63-dbb3-4682-9ec5-1cb614165051	1e7bbf40-54d5-49f3-812e-6336f876a0cd	auth.login.success	auth	info	user	1e7bbf40-54d5-49f3-812e-6336f876a0cd	{"grantType":"password","webSession":false,"deviceIdentifier":"fdbc82df-e8b9-47bd-82ad-08d88c0ddf56","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.516Z
20c3b05a-d431-42bd-915d-514b441032cd	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	system.yubico.credentials.update	security	security	system	yubico	{"method":"PUT","path":"/api/two-factor/yubikey/config","userAgent":"node"}	2026-09-29T11:48:14.526Z
38fe52b1-25ab-4018-9f94-ef74419f8270	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.audit.settings.update	system	info	auditLog	\N	{"retentionDays":365,"method":"PUT","path":"/api/admin/logs/settings","userAgent":"node"}	2026-09-29T11:48:14.528Z
f66c4ced-3c80-4025-9e15-03121674637a	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":720,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.538Z
1757871f-a014-4ad7-b7ea-ccd1c918e2f7	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":1,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.548Z
92a5f0cb-522d-4d0e-984c-470bea84a032	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.create	system	info	invite	\N	{"expiresInHours":1,"method":"POST","path":"/api/admin/invites","userAgent":"node"}	2026-09-29T11:48:14.558Z
011f1c6b-ede3-4ce9-9f54-78763c6bbac7	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.invite.delete	system	info	invite	\N	{"method":"DELETE","path":"/api/admin/invites/42f55c20b538ebcbcc1ad0490f65c3c12a8c20fb","userAgent":"node"}	2026-09-29T11:48:14.568Z
bef36b89-653b-40dc-ae0f-430ee3f3911b	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"password","webSession":false,"deviceIdentifier":"98cbc6ce-0bf3-4f1b-8437-cfe4d28ab8f8","deviceType":0,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.580Z
eeea68d1-7fdc-4c72-811a-0fed8b839b3e	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"password","webSession":true,"deviceIdentifier":"d765ae6c-f4b8-4246-8fbe-bea276f17d8f","deviceType":9,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.593Z
61d65e47-df5d-4b7a-9c54-6accb2ec319c	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"password","webSession":false,"deviceIdentifier":"fbfb5e63-dc64-4c5c-80c6-0eea840e0880","deviceType":2,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.604Z
36ac9772-2386-47ab-8f81-86531c55903a	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"password","webSession":false,"deviceIdentifier":"dc32bea1-1f41-4c00-8bc3-903c7c6f1e81","deviceType":6,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:14.616Z
8067abbe-8e7f-4dbd-a94b-dbfb050e1ede	b47224e1-7541-4fed-8262-51a236e3f206	device.name.update	device	info	device	dc32bea1-1f41-4c00-8bc3-903c7c6f1e81	{"method":"PUT","path":"/api/devices/dc32bea1-1f41-4c00-8bc3-903c7c6f1e81/name","userAgent":"node"}	2026-09-29T11:48:14.619Z
aababd5b-8014-45db-b1ad-551929f32f87	b47224e1-7541-4fed-8262-51a236e3f206	cipher.delete.soft	data	security	cipher	b34e5318-7760-4003-8120-758e8b98f1f5	{"type":6,"method":"PUT","path":"/api/ciphers/b34e5318-7760-4003-8120-758e8b98f1f5/delete","userAgent":"node"}	2026-09-29T11:48:14.677Z
3f74baa1-f3f6-424a-92ea-f9b3a9d22670	b47224e1-7541-4fed-8262-51a236e3f206	account.api_key.view	security	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"method":"POST","path":"/api/accounts/api-key","userAgent":"node"}	2026-09-29T11:48:16.091Z
f91cf1a4-2afd-4e41-8487-d5451f511f07	b47224e1-7541-4fed-8262-51a236e3f206	account.api_key.rotate	security	security	user	b47224e1-7541-4fed-8262-51a236e3f206	{"method":"POST","path":"/api/accounts/rotate-api-key","userAgent":"node"}	2026-09-29T11:48:16.105Z
7ffb0029-8d99-4e59-b208-8aeaff733008	b47224e1-7541-4fed-8262-51a236e3f206	account.api_key.view	security	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"method":"POST","path":"/api/accounts/api-key","userAgent":"node"}	2026-09-29T11:48:16.116Z
84ab379c-e0b7-425c-ae07-5f586a6c92c9	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"client_credentials","webSession":false,"deviceIdentifier":"afe5ecf0-f170-4a80-8afe-3887d3779241","deviceType":21,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:16.121Z
2e41838c-d378-4d21-89be-4606848e74cf	b47224e1-7541-4fed-8262-51a236e3f206	auth.login.success	auth	info	user	b47224e1-7541-4fed-8262-51a236e3f206	{"grantType":"password","webSession":false,"deviceIdentifier":"17992036-4808-42fe-881f-76735d1b4447","deviceType":9,"method":"POST","path":"/identity/connect/token","ip":"10.77.0.29","userAgent":"node"}	2026-09-29T11:48:16.159Z
6783f1d0-70c8-4824-b838-3f2b350cb2b8	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	cipher.delete.soft	data	security	cipher	1b1b67ae-4b3d-430f-b264-8debe2d401b1	{"type":1,"method":"PUT","path":"/api/ciphers/1b1b67ae-4b3d-430f-b264-8debe2d401b1/delete","userAgent":"node"}	2026-09-29T11:48:16.449Z
ec7dbeaa-f069-4d14-a014-c07bf9265e4c	f175fcfb-4094-43d5-9e98-b98725c0283a	account.totp.enable	security	security	user	f175fcfb-4094-43d5-9e98-b98725c0283a	{"method":"PUT","path":"/api/accounts/totp","userAgent":"node"}	2026-09-29T11:48:16.598Z
138faabe-263e-4fd6-9bfc-d152020a3803	f175fcfb-4094-43d5-9e98-b98725c0283a	auth.login.success	auth	info	user	f175fcfb-4094-43d5-9e98-b98725c0283a	{"grantType":"password","webSession":false,"deviceIdentifier":"d16c15e2-a6c0-460a-896e-2257b6931070","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:16.629Z
5993b5b6-94f3-4426-9704-72ff72f9ca14	d65ed8ce-595f-4e68-b9dc-9c54f036a177	account.yubikey.enable	security	security	user	d65ed8ce-595f-4e68-b9dc-9c54f036a177	{"method":"PUT","path":"/api/two-factor/yubikey","userAgent":"node"}	2026-09-29T11:48:16.641Z
601c32d3-30b9-4874-8d2c-97b91b94701e	d65ed8ce-595f-4e68-b9dc-9c54f036a177	auth.login.success	auth	info	user	d65ed8ce-595f-4e68-b9dc-9c54f036a177	{"grantType":"password","webSession":false,"deviceIdentifier":"b947a09e-fe15-4652-8788-9182704c4002","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:16.653Z
c799d021-c931-43c7-bfa9-dc12fd79ebb3	689390e4-7017-4751-b384-b34c8ef41116	account.webauthn_2fa.enable	security	security	accountPasskey	\N	{"method":"PUT","path":"/api/two-factor/webauthn","userAgent":"node"}	2026-09-29T11:48:16.677Z
dfe80451-69ab-43ea-ae5e-dac4ea92fb01	689390e4-7017-4751-b384-b34c8ef41116	auth.login.success	auth	info	user	689390e4-7017-4751-b384-b34c8ef41116	{"grantType":"password","webSession":false,"deviceIdentifier":"483d1b5b-3004-42e7-8f27-f84aa8234728","deviceType":25,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:16.702Z
4fa50c66-61d0-4680-a5b0-9528bed78fcd	032772a9-e7c1-4305-a14e-2ed1b3fef953	account.passkey.create	security	info	accountPasskey	af717776-95e4-4e1b-a350-26cf8bcd4b6d	{"prfStatus":0,"method":"POST","path":"/api/webauthn","userAgent":"node"}	2026-09-29T11:48:16.715Z
777e23cb-9c62-40d8-bfde-6340e1b9f72e	032772a9-e7c1-4305-a14e-2ed1b3fef953	account.passkey.create	security	info	accountPasskey	e80f2687-447b-40c8-a7c1-83a1de1ba6d8	{"prfStatus":1,"method":"POST","path":"/api/webauthn","userAgent":"node"}	2026-09-29T11:48:16.730Z
a06c1255-298d-4464-a912-a7c8150e6731	032772a9-e7c1-4305-a14e-2ed1b3fef953	account.passkey.create	security	info	accountPasskey	ef284549-a046-4e28-87a5-2fcd84ae4349	{"prfStatus":2,"method":"POST","path":"/api/webauthn","userAgent":"node"}	2026-09-29T11:48:16.744Z
cf154545-75ab-40c4-beeb-7f310b82ad23	032772a9-e7c1-4305-a14e-2ed1b3fef953	auth.passkey.login.success	auth	info	accountPasskey	af717776-95e4-4e1b-a350-26cf8bcd4b6d	{"grantType":"webauthn","webSession":false,"deviceIdentifier":"761d7da7-1af8-4a38-84a9-721861298c52","deviceType":9,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:16.750Z
0be1b9c4-b7d8-4fed-9fe5-ae8094655746	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.backup.settings.update	data	info	backup	\N	{"destinationCount":2,"scheduledDestinationCount":1,"method":"PUT","path":"/api/admin/backup/settings","userAgent":"node"}	2026-09-29T11:48:16.772Z
2a87697d-a4c8-41c0-be89-51aee2cac31b	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.user.status	security	security	user	8ac1796d-04aa-41bd-a31b-cb96118b4703	{"status":"banned","method":"PUT","path":"/api/admin/users/8ac1796d-04aa-41bd-a31b-cb96118b4703/status","userAgent":"node"}	2026-09-29T11:48:16.786Z
06009f9b-7289-4522-86f6-94ba38a29df7	502e2390-384d-40f3-83b7-53bfc6ee882c	auth.login.success	auth	info	user	502e2390-384d-40f3-83b7-53bfc6ee882c	{"grantType":"password","webSession":false,"deviceIdentifier":"f6f3bb15-e022-4fab-80ae-a779cedc9ac4","deviceType":25,"method":"POST","path":"/identity/connect/token","ip":"10.77.0.30","userAgent":"node"}	2026-09-29T11:48:32.886Z
975b21f7-b073-467f-a74e-ee4c3efdb74e	9fab75a7-a33b-412e-9dda-f934a392b545	auth.login.success	auth	info	user	9fab75a7-a33b-412e-9dda-f934a392b545	{"grantType":"client_credentials","webSession":false,"deviceIdentifier":"2a3ba310-7319-4acc-8f69-c3f7f9281f84","deviceType":21,"method":"POST","path":"/identity/connect/token","userAgent":"node"}	2026-09-29T11:48:32.907Z
a2c9e78e-4670-4468-88ff-70c0b90c4c72	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	auth.login.success	auth	info	user	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	{"grantType":"password","webSession":false,"deviceIdentifier":"601f883a-3201-44c3-8f95-72462c9203bd","deviceType":25,"method":"POST","path":"/identity/connect/token","ip":"10.77.0.32","userAgent":"node"}	2026-09-29T11:48:32.973Z
4f11679c-3b96-40d9-b759-10b66d84de34	39af72eb-5f25-4b45-8504-2e4d6c39bccd	auth.login.success	auth	info	user	39af72eb-5f25-4b45-8504-2e4d6c39bccd	{"grantType":"password","webSession":false,"deviceIdentifier":"034f057d-9e6e-4966-8c1a-2baeb063c723","deviceType":25,"method":"POST","path":"/identity/connect/token","ip":"10.77.0.33","userAgent":"node"}	2026-09-29T11:48:32.992Z
2d5cf3a9-be64-49bc-bf2e-985daafc7568	e730e934-1006-4550-a443-c12680cb0719	auth.login.success	auth	info	user	e730e934-1006-4550-a443-c12680cb0719	{"grantType":"password","webSession":false,"deviceIdentifier":"2cd6e79d-c400-4fc5-8202-f5fca5e1d846","deviceType":25,"method":"POST","path":"/identity/connect/token","ip":"10.77.0.34","userAgent":"node"}	2026-09-29T11:48:33.005Z
a403fc21-c7b3-4b47-83dd-8b17273f5c85	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	auth.login.success	auth	info	user	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	{"grantType":"password","webSession":false,"deviceIdentifier":"fe2eabce-5487-4df7-8af9-497b7f60e4c1","deviceType":25,"method":"POST","path":"/identity/connect/token","ip":"10.77.0.35","userAgent":"node"}	2026-09-29T11:48:33.016Z
a75e593f-8c05-4802-99b1-3a416b0969be	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin.backup.export	data	info	backup	\N	{"users":19,"ciphers":20,"attachments":4,"compressedBytes":72649,"includesAttachments":true,"method":"POST","path":"/api/admin/backup/export","userAgent":"node"}	2026-09-29T11:48:33.456Z
\.


--
-- Data for Name: auth_requests; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.auth_requests (id, user_id, organization_id, type, request_device_identifier, request_device_type, request_ip_address, request_country_name, response_device_identifier, access_code, public_key, key, master_password_hash, approved, creation_date, response_date, authentication_date) FROM stdin;
d5cf2a1a-46ff-49e3-b4a8-0504eba406bd	b47224e1-7541-4fed-8262-51a236e3f206	\N	0	df733cf1-c2a8-442a-8740-7bc10ced7b9d	9	10.77.0.25	\N	\N	code62a2fed3d6e08c44835fc	ZGV2aWNlLXB1YmxpYy1rZXktcGVuZGluZw==	\N	\N	\N	2026-09-29T11:48:16.125Z	\N	\N
eb01d13a-22d5-4f91-a185-490e534382b7	b47224e1-7541-4fed-8262-51a236e3f206	\N	0	ee693330-283d-46ec-86dc-de60d9d36337	9	10.77.0.26	\N	c51d72e8-0110-4bde-84b5-1938c8649ab7	code2687f86ed6784b8a5fca3	ZGV2aWNlLXB1YmxpYy1rZXktYXBwcm92ZWQ=	4.cnNhLWF1dGgtcmVxdWVzdC1rZXktZWIwMWQxM2EtMjJkNS00ZjkxLWExODUtNDkwZTUzNDM4MmI3	\N	1	2026-09-29T11:48:16.130Z	2026-09-29T11:48:16.136Z	\N
a6a0387f-dacb-4a29-a581-e2cbafc2973f	b47224e1-7541-4fed-8262-51a236e3f206	\N	0	6bcd0967-5431-4947-8255-c8430d054d57	9	10.77.0.27	\N	c51d72e8-0110-4bde-84b5-1938c8649ab7	code62d6c2330036f64bcf71b	ZGV2aWNlLXB1YmxpYy1rZXktZGVuaWVk	\N	\N	0	2026-09-29T11:48:16.141Z	2026-09-29T11:48:16.145Z	\N
611bebbf-7e1f-4154-857d-4880c7ef8680	b47224e1-7541-4fed-8262-51a236e3f206	\N	0	17992036-4808-42fe-881f-76735d1b4447	9	10.77.0.28	\N	c51d72e8-0110-4bde-84b5-1938c8649ab7	codef839161355091fcd9e33f	ZGV2aWNlLXB1YmxpYy1rZXktdXNlZA==	4.cnNhLWF1dGgtcmVxdWVzdC1rZXktNjExYmViYmYtN2UxZi00MTU0LTg1N2QtNDg4MGM3ZWY4Njgw	\N	1	2026-09-29T11:48:16.149Z	2026-09-29T11:48:16.153Z	2026-09-29T11:48:16.157Z
\.


--
-- Data for Name: cipher_collections; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.cipher_collections (cipher_id, collection_id) FROM stdin;
8f9adda7-74ef-4e10-841f-ebf53114c410	65f638b4-5ad5-4c87-806c-72fc40783e50
4bf69434-1697-471d-bb4b-67e24583adae	65f638b4-5ad5-4c87-806c-72fc40783e50
4bf69434-1697-471d-bb4b-67e24583adae	724d5b62-0182-4db1-a2c8-76df76dd973e
0150dd6c-29ee-42eb-a635-3824faedf319	724d5b62-0182-4db1-a2c8-76df76dd973e
0150dd6c-29ee-42eb-a635-3824faedf319	c63a69e7-d1f1-42ca-b327-929249b11dc2
16435347-0775-45fc-88af-c3b433258053	c63a69e7-d1f1-42ca-b327-929249b11dc2
1b1b67ae-4b3d-430f-b264-8debe2d401b1	65f638b4-5ad5-4c87-806c-72fc40783e50
1c18c69f-2cf7-46ec-b4d6-1eea37a1ac31	c63a69e7-d1f1-42ca-b327-929249b11dc2
44a372b1-cf15-4040-a2bf-9389972d48a9	1d56ca17-87b5-43e0-b85e-4675ce18f783
\.


--
-- Data for Name: cipher_user_state; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.cipher_user_state (cipher_id, user_id, folder_id, favorite, archived_at) FROM stdin;
8f9adda7-74ef-4e10-841f-ebf53114c410	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	0	\N
4bf69434-1697-471d-bb4b-67e24583adae	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	0	\N
0150dd6c-29ee-42eb-a635-3824faedf319	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	0	\N
1b1b67ae-4b3d-430f-b264-8debe2d401b1	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	0	\N
16435347-0775-45fc-88af-c3b433258053	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	0	\N
1c18c69f-2cf7-46ec-b4d6-1eea37a1ac31	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	0	\N
8f9adda7-74ef-4e10-841f-ebf53114c410	f175fcfb-4094-43d5-9e98-b98725c0283a	33773829-d164-4936-a21f-47246739c775	1	\N
16435347-0775-45fc-88af-c3b433258053	b47224e1-7541-4fed-8262-51a236e3f206	\N	0	2026-09-29T11:48:16.547Z
44a372b1-cf15-4040-a2bf-9389972d48a9	19290199-ab15-4919-823c-38b084e4e827	\N	0	\N
\.


--
-- Data for Name: ciphers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ciphers (id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) FROM stdin;
58a250b2-77e9-4f91-8005-eb397ad57bbb	b47224e1-7541-4fed-8262-51a236e3f206	\N	3	\N	2.aXYtbmFtZS1jYXJk|Y3QtbmFtZS1jYXJk|bWFjLW5hbWUtY2FyZA==	2.aXYtbm90ZXMtY2FyZA==|Y3Qtbm90ZXMtY2FyZA==|bWFjLW5vdGVzLWNhcmQ=	0	{"card":{"cardholderName":"2.aXYtaG9sZGVy|Y3QtaG9sZGVy|bWFjLWhvbGRlcg==","brand":"2.aXYtYnJhbmQ=|Y3QtYnJhbmQ=|bWFjLWJyYW5k","number":"2.aXYtbnVtYmVy|Y3QtbnVtYmVy|bWFjLW51bWJlcg==","expMonth":"2.aXYtbW9udGg=|Y3QtbW9udGg=|bWFjLW1vbnRo","expYear":"2.aXYteWVhcg==|Y3QteWVhcg==|bWFjLXllYXI=","code":"2.aXYtY29kZQ==|Y3QtY29kZQ==|bWFjLWNvZGU="},"login":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	1	\N	2026-09-29T11:48:14.654Z	2026-09-29T11:48:14.654Z	\N	\N
71a3bb4b-4bf6-4bde-b7af-d2b4d2b6be90	b47224e1-7541-4fed-8262-51a236e3f206	\N	4	\N	2.aXYtbmFtZS1pZGVudGl0eQ==|Y3QtbmFtZS1pZGVudGl0eQ==|bWFjLW5hbWUtaWRlbnRpdHk=	2.aXYtbm90ZXMtaWRlbnRpdHk=|Y3Qtbm90ZXMtaWRlbnRpdHk=|bWFjLW5vdGVzLWlkZW50aXR5	0	{"identity":{"title":"2.aXYtdGl0bGU=|Y3QtdGl0bGU=|bWFjLXRpdGxl","firstName":"2.aXYtZmlyc3Q=|Y3QtZmlyc3Q=|bWFjLWZpcnN0","middleName":"2.aXYtbWlkZGxl|Y3QtbWlkZGxl|bWFjLW1pZGRsZQ==","lastName":"2.aXYtbGFzdA==|Y3QtbGFzdA==|bWFjLWxhc3Q=","address1":"2.aXYtYWRkcmVzczE=|Y3QtYWRkcmVzczE=|bWFjLWFkZHJlc3Mx","address2":"2.aXYtYWRkcmVzczI=|Y3QtYWRkcmVzczI=|bWFjLWFkZHJlc3My","address3":"2.aXYtYWRkcmVzczM=|Y3QtYWRkcmVzczM=|bWFjLWFkZHJlc3Mz","city":"2.aXYtY2l0eQ==|Y3QtY2l0eQ==|bWFjLWNpdHk=","state":"2.aXYtc3RhdGU=|Y3Qtc3RhdGU=|bWFjLXN0YXRl","postalCode":"2.aXYtcG9zdGFs|Y3QtcG9zdGFs|bWFjLXBvc3RhbA==","country":"2.aXYtY291bnRyeQ==|Y3QtY291bnRyeQ==|bWFjLWNvdW50cnk=","company":"2.aXYtY29tcGFueQ==|Y3QtY29tcGFueQ==|bWFjLWNvbXBhbnk=","email":"2.aXYtZW1haWw=|Y3QtZW1haWw=|bWFjLWVtYWls","phone":"2.aXYtcGhvbmU=|Y3QtcGhvbmU=|bWFjLXBob25l","ssn":"2.aXYtc3Nu|Y3Qtc3Nu|bWFjLXNzbg==","username":"2.aXYtaWQtdXNlcm5hbWU=|Y3QtaWQtdXNlcm5hbWU=|bWFjLWlkLXVzZXJuYW1l","passportNumber":"2.aXYtaWQtcGFzc3BvcnQ=|Y3QtaWQtcGFzc3BvcnQ=|bWFjLWlkLXBhc3Nwb3J0","licenseNumber":"2.aXYtaWQtbGljZW5zZQ==|Y3QtaWQtbGljZW5zZQ==|bWFjLWlkLWxpY2Vuc2U="},"login":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	2.aXYtaWRlbnRpdHktY2lwaGVyLWtleQ==|Y3QtaWRlbnRpdHktY2lwaGVyLWtleQ==|bWFjLWlkZW50aXR5LWNpcGhlci1rZXk=	2026-09-29T11:48:14.658Z	2026-09-29T11:48:14.658Z	\N	\N
b5a9593a-55fb-4e7f-8fa4-f0de7fa22662	b47224e1-7541-4fed-8262-51a236e3f206	\N	7	\N	2.aXYtbmFtZS1kcml2ZXJzLWxpY2Vuc2U=|Y3QtbmFtZS1kcml2ZXJzLWxpY2Vuc2U=|bWFjLW5hbWUtZHJpdmVycy1saWNlbnNl	2.aXYtbm90ZXMtZHJpdmVycy1saWNlbnNl|Y3Qtbm90ZXMtZHJpdmVycy1saWNlbnNl|bWFjLW5vdGVzLWRyaXZlcnMtbGljZW5zZQ==	0	{"driversLicense":{"firstName":"2.aXYtZGwtZmlyc3Q=|Y3QtZGwtZmlyc3Q=|bWFjLWRsLWZpcnN0","lastName":"2.aXYtZGwtbGFzdA==|Y3QtZGwtbGFzdA==|bWFjLWRsLWxhc3Q=","licenseNumber":"2.aXYtbGljZW5zZQ==|Y3QtbGljZW5zZQ==|bWFjLWxpY2Vuc2U=","issuingCountry":"2.aXYtZGwtY291bnRyeQ==|Y3QtZGwtY291bnRyeQ==|bWFjLWRsLWNvdW50cnk="},"login":null,"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:14.664Z	2026-09-29T11:48:14.664Z	\N	\N
d864233b-48c6-48b9-888a-13f727aae34f	b47224e1-7541-4fed-8262-51a236e3f206	\N	8	\N	2.aXYtbmFtZS1wYXNzcG9ydA==|Y3QtbmFtZS1wYXNzcG9ydA==|bWFjLW5hbWUtcGFzc3BvcnQ=	2.aXYtbm90ZXMtcGFzc3BvcnQ=|Y3Qtbm90ZXMtcGFzc3BvcnQ=|bWFjLW5vdGVzLXBhc3Nwb3J0	0	{"passport":{"surname":"2.aXYtc3VybmFtZQ==|Y3Qtc3VybmFtZQ==|bWFjLXN1cm5hbWU=","givenName":"2.aXYtZ2l2ZW4=|Y3QtZ2l2ZW4=|bWFjLWdpdmVu","passportNumber":"2.aXYtcGFzc3BvcnQ=|Y3QtcGFzc3BvcnQ=|bWFjLXBhc3Nwb3J0","nationality":"2.aXYtbmF0aW9uYWxpdHk=|Y3QtbmF0aW9uYWxpdHk=|bWFjLW5hdGlvbmFsaXR5"},"login":null,"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:14.667Z	2026-09-29T11:48:14.667Z	\N	\N
b34e5318-7760-4003-8120-758e8b98f1f5	b47224e1-7541-4fed-8262-51a236e3f206	\N	6	\N	2.aXYtbmFtZS1iYW5rLWFjY291bnQ=|Y3QtbmFtZS1iYW5rLWFjY291bnQ=|bWFjLW5hbWUtYmFuay1hY2NvdW50	2.aXYtbm90ZXMtYmFuay1hY2NvdW50|Y3Qtbm90ZXMtYmFuay1hY2NvdW50|bWFjLW5vdGVzLWJhbmstYWNjb3VudA==	0	{"bankAccount":{"bankName":"2.aXYtYmFuaw==|Y3QtYmFuaw==|bWFjLWJhbms=","accountNumber":"2.aXYtYWNjb3VudA==|Y3QtYWNjb3VudA==|bWFjLWFjY291bnQ=","routingNumber":"2.aXYtcm91dGluZw==|Y3Qtcm91dGluZw==|bWFjLXJvdXRpbmc=","iban":"2.aXYtaWJhbg==|Y3QtaWJhbg==|bWFjLWliYW4=","swiftCode":"2.aXYtc3dpZnQ=|Y3Qtc3dpZnQ=|bWFjLXN3aWZ0"},"login":null,"card":null,"identity":null,"secureNote":null,"sshKey":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:14.662Z	2026-09-29T11:48:14.675Z	\N	2026-09-29T11:48:14.675Z
620fe39b-4de1-4b3f-a180-00f8fb91f1bd	b47224e1-7541-4fed-8262-51a236e3f206	\N	2	36b2d31c-e6dc-4382-91b6-1c34359e23c0	2.aXYtbmFtZS1ub3Rl|Y3QtbmFtZS1ub3Rl|bWFjLW5hbWUtbm90ZQ==	2.aXYtbm90ZXMtbm90ZQ==|Y3Qtbm90ZXMtbm90ZQ==|bWFjLW5vdGVzLW5vdGU=	0	{"secureNote":{"type":0},"login":null,"card":null,"identity":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:14.644Z	2026-09-29T11:48:15.897Z	\N	\N
16435347-0775-45fc-88af-c3b433258053	\N	4978de20-9a02-4877-a193-048eaa0d30ce	3	\N	2.aXYtb3JnLW5hbWUtY2FyZC1vcGVyYXRpb25z|Y3Qtb3JnLW5hbWUtY2FyZC1vcGVyYXRpb25z|bWFjLW9yZy1uYW1lLWNhcmQtb3BlcmF0aW9ucw==	\N	0	{"card":{"cardholderName":"2.aXYtb3JnLWhvbGRlcg==|Y3Qtb3JnLWhvbGRlcg==|bWFjLW9yZy1ob2xkZXI=","number":"2.aXYtb3JnLW51bWJlcg==|Y3Qtb3JnLW51bWJlcg==|bWFjLW9yZy1udW1iZXI="},"login":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.414Z	2026-09-29T11:48:16.479Z	\N	\N
44a372b1-cf15-4040-a2bf-9389972d48a9	\N	844847a4-f6fd-4267-9990-b8eba5516b49	1	\N	2.aXYtb3JnMi1sb2dpbg==|Y3Qtb3JnMi1sb2dpbg==|bWFjLW9yZzItbG9naW4=	\N	0	{"login":{"username":"2.aXYtb3JnMi11c2Vy|Y3Qtb3JnMi11c2Vy|bWFjLW9yZzItdXNlcg==","fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.561Z	2026-09-29T11:48:16.561Z	\N	\N
46969ace-fb38-4c56-a7de-b7c9330b00ac	b47224e1-7541-4fed-8262-51a236e3f206	\N	5	\N	2.aXYtbmFtZS1zc2gta2V5|Y3QtbmFtZS1zc2gta2V5|bWFjLW5hbWUtc3NoLWtleQ==	2.aXYtbm90ZXMtc3NoLWtleQ==|Y3Qtbm90ZXMtc3NoLWtleQ==|bWFjLW5vdGVzLXNzaC1rZXk=	0	{"sshKey":{"privateKey":"2.aXYtc3NoLXByaXZhdGU=|Y3Qtc3NoLXByaXZhdGU=|bWFjLXNzaC1wcml2YXRl","publicKey":"2.aXYtc3NoLXB1YmxpYw==|Y3Qtc3NoLXB1YmxpYw==|bWFjLXNzaC1wdWJsaWM=","keyFingerprint":"2.aXYtc3NoLWZpbmdlcnByaW50|Y3Qtc3NoLWZpbmdlcnByaW50|bWFjLXNzaC1maW5nZXJwcmludA==","fingerprint":"2.aXYtc3NoLWZpbmdlcnByaW50|Y3Qtc3NoLWZpbmdlcnByaW50|bWFjLXNzaC1maW5nZXJwcmludA=="},"login":null,"card":null,"identity":null,"secureNote":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:14.660Z	2026-09-29T11:48:14.671Z	2026-09-29T11:48:14.671Z	\N
cdf52ff2-f10a-4093-94a6-e1ec53c5b98d	b47224e1-7541-4fed-8262-51a236e3f206	\N	1	\N	2.aXYtbmFtZS1rZXktYWRkZWQ=|Y3QtbmFtZS1rZXktYWRkZWQ=|bWFjLW5hbWUta2V5LWFkZGVk	2.aXYtbm90ZXMta2V5LWFkZGVk|Y3Qtbm90ZXMta2V5LWFkZGVk|bWFjLW5vdGVzLWtleS1hZGRlZA==	0	{"login":{"username":"2.aXYta2EtdXNlcg==|Y3Qta2EtdXNlcg==|bWFjLWthLXVzZXI=","password":"2.aXYta2EtcGFzcw==|Y3Qta2EtcGFzcw==|bWFjLWthLXBhc3M=","fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null,"lastKnownRevisionDate":"2026-09-29T11:48:14.679Z","keyAddedFromRevision":"2026-09-29T11:48:14.679Z"}	0	2.aXYta2V5LWFkZGVkLWNpcGhlci1rZXk=|Y3Qta2V5LWFkZGVkLWNpcGhlci1rZXk=|bWFjLWtleS1hZGRlZC1jaXBoZXIta2V5	2026-09-29T11:48:14.679Z	2026-09-29T11:48:15.791Z	\N	\N
0150dd6c-29ee-42eb-a635-3824faedf319	\N	4978de20-9a02-4877-a193-048eaa0d30ce	2	\N	2.aXYtb3JnLW5hbWUtbm90ZS1maW5hbmNlLW9wZXJhdGlvbnM=|Y3Qtb3JnLW5hbWUtbm90ZS1maW5hbmNlLW9wZXJhdGlvbnM=|bWFjLW9yZy1uYW1lLW5vdGUtZmluYW5jZS1vcGVyYXRpb25z	\N	0	{"secureNote":{"type":0},"login":null,"card":null,"identity":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.396Z	2026-09-29T11:48:16.396Z	\N	\N
254ad6b2-e022-4be5-b164-0cb07dd3b202	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	2	\N	2.aXYtbmFtZS1hZG1pbi1wZXJzb25hbA==|Y3QtbmFtZS1hZG1pbi1wZXJzb25hbA==|bWFjLW5hbWUtYWRtaW4tcGVyc29uYWw=	2.aXYtbm90ZXMtYWRtaW4tcGVyc29uYWw=|Y3Qtbm90ZXMtYWRtaW4tcGVyc29uYWw=|bWFjLW5vdGVzLWFkbWluLXBlcnNvbmFs	0	{"secureNote":{"type":0},"login":null,"card":null,"identity":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.515Z	2026-09-29T11:48:16.515Z	\N	\N
910c82d8-9833-453c-97c2-da58b5a1f7a4	1e7bbf40-54d5-49f3-812e-6336f876a0cd	\N	2	\N	2.aXYtbGVnYWN5LXBhc2NhbC1rZXlz|Y3QtbGVnYWN5LXBhc2NhbC1rZXlz|bWFjLWxlZ2FjeS1wYXNjYWwta2V5cw==	\N	0	{"secureNote":{"type":0},"login":null,"card":null,"identity":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null,"Id":"ffffffff-ffff-4fff-8fff-ffffffffffff","Edit":false,"ViewPassword":false,"OrganizationUseTotp":false,"RevisionDate":"2020-01-01T00:00:00.000Z","Object":"cipher"}	0	\N	2026-09-29T11:48:16.793Z	2026-09-29T11:48:16.793Z	\N	\N
5fe98dcb-b6a0-4238-a48d-eb35fa237f20	b47224e1-7541-4fed-8262-51a236e3f206	\N	1	72b3055f-729c-45b7-8fc2-9f053d8a37fa	2.aXYtbmFtZS1sb2dpbg==|Y3QtbmFtZS1sb2dpbg==|bWFjLW5hbWUtbG9naW4=	2.aXYtbm90ZXMtbG9naW4=|Y3Qtbm90ZXMtbG9naW4=|bWFjLW5vdGVzLWxvZ2lu	1	{"login":{"username":"2.aXYtdXNlcm5hbWU=|Y3QtdXNlcm5hbWU=|bWFjLXVzZXJuYW1l","password":"2.aXYtcGFzc3dvcmQ=|Y3QtcGFzc3dvcmQ=|bWFjLXBhc3N3b3Jk","totp":"2.aXYtdG90cC11cmk=|Y3QtdG90cC11cmk=|bWFjLXRvdHAtdXJp","passwordRevisionDate":"2025-01-02T03:04:05.000Z","uris":[{"uri":"2.aXYtdXJpLWRvbWFpbg==|Y3QtdXJpLWRvbWFpbg==|bWFjLXVyaS1kb21haW4=","uriChecksum":"2.aXYtdXJpLWRvbWFpbi1jaGVja3N1bQ==|Y3QtdXJpLWRvbWFpbi1jaGVja3N1bQ==|bWFjLXVyaS1kb21haW4tY2hlY2tzdW0=","match":0},{"uri":"2.aXYtdXJpLWV4YWN0|Y3QtdXJpLWV4YWN0|bWFjLXVyaS1leGFjdA==","match":3},{"uri":"2.aXYtdXJpLWRlZmF1bHQ=|Y3QtdXJpLWRlZmF1bHQ=|bWFjLXVyaS1kZWZhdWx0","match":null}],"fido2Credentials":[{"credentialId":"2.aXYtZmlkbzItY3JlZGVudGlhbC1pZA==|Y3QtZmlkbzItY3JlZGVudGlhbC1pZA==|bWFjLWZpZG8yLWNyZWRlbnRpYWwtaWQ=","keyType":"2.aXYtcHVibGljLWtleQ==|Y3QtcHVibGljLWtleQ==|bWFjLXB1YmxpYy1rZXk=","keyAlgorithm":"2.aXYtRUNEU0E=|Y3QtRUNEU0E=|bWFjLUVDRFNB","keyCurve":"2.aXYtUC0yNTY=|Y3QtUC0yNTY=|bWFjLVAtMjU2","keyValue":"2.aXYtZmlkbzIta2V5LXZhbHVl|Y3QtZmlkbzIta2V5LXZhbHVl|bWFjLWZpZG8yLWtleS12YWx1ZQ==","rpId":"2.aXYtZmlkbzIuZXhhbXBsZQ==|Y3QtZmlkbzIuZXhhbXBsZQ==|bWFjLWZpZG8yLmV4YW1wbGU=","userHandle":"2.aXYtZmlkbzItdXNlci1oYW5kbGU=|Y3QtZmlkbzItdXNlci1oYW5kbGU=|bWFjLWZpZG8yLXVzZXItaGFuZGxl","userName":"2.aXYtZmlkbzItdXNlcg==|Y3QtZmlkbzItdXNlcg==|bWFjLWZpZG8yLXVzZXI=","counter":"2.aXYtMA==|Y3QtMA==|bWFjLTA=","rpName":"2.aXYtRmlkbzIgRXhhbXBsZQ==|Y3QtRmlkbzIgRXhhbXBsZQ==|bWFjLUZpZG8yIEV4YW1wbGU=","userDisplayName":"2.aXYtRmlkbzIgVXNlcg==|Y3QtRmlkbzIgVXNlcg==|bWFjLUZpZG8yIFVzZXI=","discoverable":"2.aXYtdHJ1ZQ==|Y3QtdHJ1ZQ==|bWFjLXRydWU=","creationDate":"2025-03-04T05:06:07.000Z"}]},"fields":[{"name":"2.aXYtZmllbGQtdGV4dA==|Y3QtZmllbGQtdGV4dA==|bWFjLWZpZWxkLXRleHQ=","value":"2.aXYtZmllbGQtdGV4dC12YWx1ZQ==|Y3QtZmllbGQtdGV4dC12YWx1ZQ==|bWFjLWZpZWxkLXRleHQtdmFsdWU=","type":0,"linkedId":null},{"name":"2.aXYtZmllbGQtaGlkZGVu|Y3QtZmllbGQtaGlkZGVu|bWFjLWZpZWxkLWhpZGRlbg==","value":"2.aXYtZmllbGQtaGlkZGVuLXZhbHVl|Y3QtZmllbGQtaGlkZGVuLXZhbHVl|bWFjLWZpZWxkLWhpZGRlbi12YWx1ZQ==","type":1,"linkedId":null},{"name":"2.aXYtZmllbGQtYm9vbGVhbg==|Y3QtZmllbGQtYm9vbGVhbg==|bWFjLWZpZWxkLWJvb2xlYW4=","value":"2.aXYtdHJ1ZQ==|Y3QtdHJ1ZQ==|bWFjLXRydWU=","type":2,"linkedId":null},{"name":"2.aXYtZmllbGQtbGlua2Vk|Y3QtZmllbGQtbGlua2Vk|bWFjLWZpZWxkLWxpbmtlZA==","value":null,"type":3,"linkedId":100}],"passwordHistory":[{"password":"2.aXYtb2xkLXBhc3N3b3JkLTE=|Y3Qtb2xkLXBhc3N3b3JkLTE=|bWFjLW9sZC1wYXNzd29yZC0x","lastUsedDate":"2024-12-01T00:00:00.000Z"},{"password":"2.aXYtb2xkLXBhc3N3b3JkLTI=|Y3Qtb2xkLXBhc3N3b3JkLTI=|bWFjLW9sZC1wYXNzd29yZC0y","lastUsedDate":"2025-01-01T00:00:00.000Z"}],"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null}	0	\N	2026-09-29T11:48:14.631Z	2026-09-29T11:48:15.876Z	\N	\N
8f9adda7-74ef-4e10-841f-ebf53114c410	\N	4978de20-9a02-4877-a193-048eaa0d30ce	1	\N	2.aXYtb3JnLW5hbWUtbG9naW4tZW5naW5lZXJpbmc=|Y3Qtb3JnLW5hbWUtbG9naW4tZW5naW5lZXJpbmc=|bWFjLW9yZy1uYW1lLWxvZ2luLWVuZ2luZWVyaW5n	\N	0	{"login":{"username":"2.aXYtb3JnLXVzZXI=|Y3Qtb3JnLXVzZXI=|bWFjLW9yZy11c2Vy","password":"2.aXYtb3JnLXBhc3M=|Y3Qtb3JnLXBhc3M=|bWFjLW9yZy1wYXNz","uris":[{"uri":"2.aXYtb3JnLXVyaQ==|Y3Qtb3JnLXVyaQ==|bWFjLW9yZy11cmk=","match":null}],"fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.358Z	2026-09-29T11:48:16.358Z	\N	\N
4bf69434-1697-471d-bb4b-67e24583adae	\N	4978de20-9a02-4877-a193-048eaa0d30ce	1	\N	2.aXYtb3JnLW5hbWUtbG9naW4tc2hhcmVk|Y3Qtb3JnLW5hbWUtbG9naW4tc2hhcmVk|bWFjLW9yZy1uYW1lLWxvZ2luLXNoYXJlZA==	\N	0	{"login":{"username":"2.aXYtc2hhcmVkLXVzZXI=|Y3Qtc2hhcmVkLXVzZXI=|bWFjLXNoYXJlZC11c2Vy","password":"2.aXYtc2hhcmVkLXBhc3M=|Y3Qtc2hhcmVkLXBhc3M=|bWFjLXNoYXJlZC1wYXNz","fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	2.aXYtb3JnLWNpcGhlci1rZXk=|Y3Qtb3JnLWNpcGhlci1rZXk=|bWFjLW9yZy1jaXBoZXIta2V5	2026-09-29T11:48:16.378Z	2026-09-29T11:48:16.378Z	\N	\N
1b1b67ae-4b3d-430f-b264-8debe2d401b1	\N	4978de20-9a02-4877-a193-048eaa0d30ce	1	\N	2.aXYtb3JnLW5hbWUtZGVsZXRlZA==|Y3Qtb3JnLW5hbWUtZGVsZXRlZA==|bWFjLW9yZy1uYW1lLWRlbGV0ZWQ=	\N	0	{"login":{"username":"2.aXYtZGVsZXRlZC11c2Vy|Y3QtZGVsZXRlZC11c2Vy|bWFjLWRlbGV0ZWQtdXNlcg==","fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.429Z	2026-09-29T11:48:16.444Z	\N	2026-09-29T11:48:16.444Z
1c18c69f-2cf7-46ec-b4d6-1eea37a1ac31	\N	4978de20-9a02-4877-a193-048eaa0d30ce	1	\N	2.aXYtbmFtZS1hZG1pbi1zaGFyZWQ=|Y3QtbmFtZS1hZG1pbi1zaGFyZWQ=|bWFjLW5hbWUtYWRtaW4tc2hhcmVk	2.aXYtbm90ZXMtYWRtaW4tc2hhcmVk|Y3Qtbm90ZXMtYWRtaW4tc2hhcmVk|bWFjLW5vdGVzLWFkbWluLXNoYXJlZA==	0	{"login":{"username":"2.aXYtYWRtaW4tdXNlcg==|Y3QtYWRtaW4tdXNlcg==|bWFjLWFkbWluLXVzZXI=","fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.488Z	2026-09-29T11:48:16.496Z	\N	\N
c2a66bb4-d4ea-4e15-90b1-fe8783eb52e6	1e7bbf40-54d5-49f3-812e-6336f876a0cd	\N	1	\N	\N	\N	0	{"login":{"username":"2.aXYtbGVnYWN5LXVzZXI=|Y3QtbGVnYWN5LXVzZXI=|bWFjLWxlZ2FjeS11c2Vy","fido2Credentials":null},"card":null,"identity":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null,"name":"2.aXYtbGVnYWN5LWFsbC1pbi1kYXRh|Y3QtbGVnYWN5LWFsbC1pbi1kYXRh|bWFjLWxlZ2FjeS1hbGwtaW4tZGF0YQ==","notes":"2.aXYtbGVnYWN5LWFsbC1pbi1kYXRhLW5vdGVz|Y3QtbGVnYWN5LWFsbC1pbi1kYXRhLW5vdGVz|bWFjLWxlZ2FjeS1hbGwtaW4tZGF0YS1ub3Rlcw==","key":"2.aXYtbGVnYWN5LWFsbC1pbi1kYXRhLWtleQ==|Y3QtbGVnYWN5LWFsbC1pbi1kYXRhLWtleQ==|bWFjLWxlZ2FjeS1hbGwtaW4tZGF0YS1rZXk=","reprompt":1,"folderId":"a2656d34-484f-4062-97fc-f1facabea164"}	\N	\N	2026-09-29T11:48:16.789Z	2026-09-29T11:48:16.789Z	\N	\N
71d6478d-0340-4461-8790-7e87e7c28c1c	1e7bbf40-54d5-49f3-812e-6336f876a0cd	\N	5	\N	2.aXYtbGVnYWN5LXNzaC1hbGlhcw==|Y3QtbGVnYWN5LXNzaC1hbGlhcw==|bWFjLWxlZ2FjeS1zc2gtYWxpYXM=	\N	0	{"sshKey":{"privateKey":"2.aXYtbGVnYWN5LXNzaC1wcml2YXRl|Y3QtbGVnYWN5LXNzaC1wcml2YXRl|bWFjLWxlZ2FjeS1zc2gtcHJpdmF0ZQ==","publicKey":"2.aXYtbGVnYWN5LXNzaC1wdWJsaWM=|Y3QtbGVnYWN5LXNzaC1wdWJsaWM=|bWFjLWxlZ2FjeS1zc2gtcHVibGlj","fingerprint":"2.aXYtbGVnYWN5LXNzaC1maW5nZXJwcmludA==|Y3QtbGVnYWN5LXNzaC1maW5nZXJwcmludA==|bWFjLWxlZ2FjeS1zc2gtZmluZ2VycHJpbnQ="},"login":null,"card":null,"identity":null,"secureNote":null,"bankAccount":null,"driversLicense":null,"passport":null,"passwordHistory":null,"fields":null}	0	\N	2026-09-29T11:48:16.797Z	2026-09-29T11:48:16.797Z	\N	\N
\.


--
-- Data for Name: collection_members; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.collection_members (collection_id, membership_id, read_only, hide_passwords, manage) FROM stdin;
65f638b4-5ad5-4c87-806c-72fc40783e50	71e73581-d6b4-4f1f-a056-2d5cc59fabc4	0	0	0
c63a69e7-d1f1-42ca-b327-929249b11dc2	71e73581-d6b4-4f1f-a056-2d5cc59fabc4	0	0	1
65f638b4-5ad5-4c87-806c-72fc40783e50	c04561f1-e4f6-4593-8934-22d7184f1590	1	1	0
724d5b62-0182-4db1-a2c8-76df76dd973e	c04561f1-e4f6-4593-8934-22d7184f1590	1	0	0
724d5b62-0182-4db1-a2c8-76df76dd973e	a528efc7-6194-4ace-a74c-bbc0d1b9aa56	0	0	0
65f638b4-5ad5-4c87-806c-72fc40783e50	f63f83a8-a800-497a-9cec-a6ef434748c3	0	0	0
724d5b62-0182-4db1-a2c8-76df76dd973e	15c8746d-6e66-4f6e-8515-aaab77516f4d	0	1	0
c63a69e7-d1f1-42ca-b327-929249b11dc2	d92349eb-d8a5-4289-9adb-cd3ca7c03173	0	0	0
\.


--
-- Data for Name: collections; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.collections (id, org_id, name, external_id, created_at, updated_at) FROM stdin;
65f638b4-5ad5-4c87-806c-72fc40783e50	4978de20-9a02-4877-a193-048eaa0d30ce	2.aXYtY29sbGVjdGlvbi1lbmdpbmVlcmluZw==|Y3QtY29sbGVjdGlvbi1lbmdpbmVlcmluZw==|bWFjLWNvbGxlY3Rpb24tZW5naW5lZXJpbmc=	\N	2026-09-29T11:48:16.162Z	2026-09-29T11:48:16.162Z
724d5b62-0182-4db1-a2c8-76df76dd973e	4978de20-9a02-4877-a193-048eaa0d30ce	2.aXYtY29sbGVjdGlvbi1maW5hbmNl|Y3QtY29sbGVjdGlvbi1maW5hbmNl|bWFjLWNvbGxlY3Rpb24tZmluYW5jZQ==	\N	2026-09-29T11:48:16.171Z	2026-09-29T11:48:16.171Z
c63a69e7-d1f1-42ca-b327-929249b11dc2	4978de20-9a02-4877-a193-048eaa0d30ce	2.aXYtY29sbGVjdGlvbi1vcGVyYXRpb25z|Y3QtY29sbGVjdGlvbi1vcGVyYXRpb25z|bWFjLWNvbGxlY3Rpb24tb3BlcmF0aW9ucw==	\N	2026-09-29T11:48:16.179Z	2026-09-29T11:48:16.179Z
1d56ca17-87b5-43e0-b85e-4675ce18f783	844847a4-f6fd-4267-9990-b8eba5516b49	2.aXYtY29sbGVjdGlvbi1hcmdvbi1kZWZhdWx0|Y3QtY29sbGVjdGlvbi1hcmdvbi1kZWZhdWx0|bWFjLWNvbGxlY3Rpb24tYXJnb24tZGVmYXVsdA==	\N	2026-09-29T11:48:16.551Z	2026-09-29T11:48:16.551Z
\.


--
-- Data for Name: config; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.config (key, value) FROM stdin;
schema.version	2026-09-27-user-key-id
registered	true
globalSettings__yubico__clientId	424242
globalSettings__yubico__key	bGVnYWN5LWZpeHR1cmUteXViaWM=
audit.logs.settings.v1	{"retentionDays":365,"maxEntries":null}
backup.settings.v1	{"version":2,"runtime":{"iv":"IdiZAfF1a3o3DLfh","ciphertext":"wD4irWcxxp6AHWb6hyqNXzQEzRyVf/X/mZYn2S9ftxLJP9RILv0hkbEmv/1QKoY0VO5r5c2UMjoGMeoirSPB7RhCgg48UY5bjEARRYUBkoGtk4E3z86rqYXangSSCxxWbaWs8ohAZvrXT6J3LgDUfVQTfQ82ZTfCBYndn62mrcRlCK3BTn2TkY4z16SoEU2LH6K/o5jQlyI44yvhuW/t9CG0dpR+3sRp+pmH2e1eUXCS1Z/A/IXv21iFdQjgS0SOxp56HMwBEcFL2rphP3Bb/rnz6xsRN7lensTnSnyMvhuRqDRYcA9JjYS8x1uB1cMOA8UbWTqPkKCk7R6D6ygmvtVhPbc10MMj8Naj7UvDFYYtnUR4SFpNC6fzuZXVo3Fhq1t6NAPl79taSMb7XK7qyFRcZEtxY6BGassJTknUdD7t+t7HVs792T8eMLI9ZuKqQrDKpFkhqZAzK46bPKkyTZ4xlGTNL6Z18qOtXSxbc82ntx5HWuROp9Y+KxQ+PpaXp+6Wrvtz/k6BSMjwtPSXHATZU0E9HOvOjBaBoYSmYm2CVMDYZ978aqdn5vEnNAZZvb3VWzcjG1YOlX/fX66Xn+UsQ+bySIKVtuXRfmGhLPIZNfv0D6WcVFblGTDeFXlcRaOEYNpF9iFlWgrIXx6V30aY2stWJ0C4tPQvd01WpziAs34KBYMN9vc0WyC9iNSkC0HeuIkqcxeEvh0p7VooGxNmG2azicGGs/SdKpEn1BcrBemhTLsu4eBApByT0KiF7zElmZqwKSR7qn3lkHTs/aHnCSVLraGkrhW1gDVW3vah+Mr8+gmkH38DGReb78cfA9FUr2CtQU9iEPBBAEcCqfIa4w2kcfyukq+mAiwmF4edbMGGIqm3YbwgAsjzJH+F9XPvbS0LnETq/DZLaYsZz6PR4Iwnb/g6FWX/xTIjw5GQg4jvxA8wqiAg7+q1ugLIPWkC71rzglvnWU0jA0aEBl81MvoUDSi9g084M4fXRAE6t0+aPsWcwEI5DcScACzZF91J7BDKxy6nWprDM1uoPaTp+LwdzCDo12+G0qu83KMZ5oW3nHyhB5//OYrlueN22jQIymFHaHY/XV+vKTKv+srtmLZ7mueldrV6lWdbFUDsaGPMol5ejAFdK0NnwDH0Avin5DUQQGcL7f+x1aciIoaKQMSkAnVWke3/9CjrLguwTCSiOqKRJTFwm3HUU3j0lkbVbHrdMmFcRjb3gx5ds0KMpJozQZE3MwGcLNqqBezStu4mDDOnmQBgkab+65j9UQG2XxSNAaBFWYygl9l/2wrktknGKI2XaBaxK9Qk8TNWo0rUewlQo051i3H3O1fzuDUyHUYlP+ZC7tUPmZ71FSCjfqFBlqK8r6o57pzPYTeKRzi+OARW4LpqliREp5aUuIqwm7QBH0b45k9mAdhanEskPyZmOunzXhKVAJu5/mdAsFzNM8uUT7lw5Gvk5pG4pLNFU0nlQdSU0PKHKCW0iOwVc+tuw7hL9jmy7BC16+x6mCYL50i8WDxWv0h7iHD7b+Khm8wD/S/Hde+v9SgsPjpHvclnwjSeIubtrz00KXTCdZM0glWQRCVVnk85k63BWoO2yFwP6gi9oaeSI9nyu/nmnkeopMfLWZIZMRstgOT8mjNlkOaBHIh7I2MlQuEMQcycAMUygAUOcMiH84HNXH41WnlW+9Fg8pgAEa158OdavxTlL+1Aiyb8ndT/IS2pjrl1QzI5xmP6RhsR6Ieb8Q1JYbQIiBoQqRXPIgXGa+cTWw=="},"portable":{"iv":"obnqYjYcw9ghlh9k","ciphertext":"z052g54AU812DzcCilyQeDdS4gTHQVb0kI2GtpPWt7BHPKAJhDxt220U6L5+wuzjMIr1Ppmh4VAAWWnGmT+osyk+tg4d4HEMtnZpVLHldcuaBFu5YhEanKvDxHedAFJf9RFNqcNAkmSqlfxEevCg6sNxhwGF1EjcsNwiv+Mlhzdc4EyYTDJa7YF1cv72q0OQObDdM9MJN0/+Ayna/R22NLH52DgqCXG2C0Kj/HnzpqHxSmUizxCOUD4f7kJtgx6squQIDHRgUHrtom+PbHbdBFx64EziqtyfjFixz/GLssfLZUY0eKOyktTx5ud+pAQVEumOTi3cPsOJlV3/SB58H7hMrGCgvUzdnZnBTCO3e+bmcaOzA4+YBbJZGqoGYllGkLv+U1AuutTYTzbI6zANBn3iJJnmMl/rXUNYLuIvBPpE7J5IDMCbT47s8GgftYceDIdB9GiQNzGBtYE5uVs29fYI0yWXP1bGmiiC513xF66LS/vioCGumIMmwM9buXTrh5ga876ET+woyekXUpxOCzxvqvwx3E5AmmIDDxt9pX/tvbw09O+u5T7oVI1JrGmzV7hHA5QQb+3LNTkTmKZiI8w4sSZIIFDmjtcVwsUsNA2cDqx052O1PMYcOPftG6rzx4g977Nz6AgdPyww3+3sAgVAhHm+/xorciDRHG580HaSYml5JZHppENH2hD4U55Mj2v8Bf97pqFR8XjnhDUBMHrhkZj0cZeGx+sBGkAcgsFVCVuTKLaVQYipBd7J4t6taerObLjqRcyVFdpPRn00n5SusgdJYGwOCq0jJZJI+8ZFDXlenX3HAwzVMShPfEmNwnYPwCyBHNWjDR7P09U1Yc9ZJui37SFWltOI+gMpq3rEjH7PJ7Ylfm/Bbm9L1QjZYQJfGbQem8dy9frCxDd9Ng1M1ehPi59jt89GwMdR9ZC6tzhSiv9KGmCcGTZrTF/45InXrGRs2/IeRFxwPJjYkq9DNot6XIW8FLHl8ojKM4vsUU2SjjHV2xvwflgQPl1giGbOtzTJb+i7k3uH2RJP64pjbSvXIygnTWIMFKAdmqvPZuKEbJvk0eSTRBB3wW2HUBTRjCYr0X92L0KZ28yVq9rw3Rwv9OznQmptWSR/NvijCrGe9h2TdmWM7RZJtwZ00+CuHOVuJPs4Dd4bBMRK5ILYC/dUajYcO4LtHsdpthPcAiCkfThacZt8+k2zBLQGKJvNq2XGWpEJUc7UHjSqdsaJqjAueZogq0XKtAw+ufPProRg5OqMvC4oXbjatVJALL6QqF4iX9YFt7VOPqeL8oqJ6it9GBPd57b3TSwd9uwa9KV7hAR+k4tRXJTorP3Tm1YNz+GSgOuHrpNJtR45zreOwjsrz8zUoE8+5cFk0D2hj5D3BAca4S7SOVBtyzFmGQJ8EvUKFzg2UidjxY8h5xGpYNBWugvwTaFChv0cNK8FeE2Hu1HBLH4c/gBHFpHQYRG3eQzQfQ5f7363+bHAU/jeeoMsboWzCPZuLekA4ke+hL5Cxk1IZA7TaHpLuaDihjJtF8AI+aETfO2ljb4LkB4Rj8T3xVG1/lYqV6lXToySbrPJ9fn4Yb6wHLJmL3CYldrSV9GiJ63NMQUKMbYin058DMEjeyjqEJUNoesS6dUJ1mqzqotvqyN+O0lP0iQO7OhAsH2khaMncjtXC/RK6VPWHqz+jJ2zCwXcV5jynXE7pvKd3EXR/wkWs+p7jVS7mOYdYndZCqsrdU9+38nlgcUU5pYOwxIqLbaoMUmnTq3b5w==","wraps":[{"userId":"42ee4466-c20c-44ec-b8d2-4c4b82d60fe4","wrappedKey":"jxG1zwUqGMc9Z+IN83y/cNzGx/K/NC3XxEyzmNYlXlmMyS/bx2jxobs879Fs6Ck2blwajJA4fdrb082fkMkQTrhGLfaW0DDULy4geTATIqw3c3mFa6AxsivGPPcb/wnvCDQnh6fvYoE/e0lAKm2js9TqBmAXY1EwZX+kZyhVsXyTxLPiumXrFS1v4fmQ3iKPUyqjusm5HxonCUnWG0a6lJL7sSgoCPjhGvaxjusEH7o3uZ6/31/yBDREjVJd7Skq8unmZ7XGKNN+jsR6yTo0hD4YlbWo95HkJa9CMZGKnJ3JrI7yTjKy7/36fNnTY5jQdsz0yiPMT6Rhru0nqbc66Q=="}]}}
backup.runtime.v1	{"version":1,"destinations":{"fixture-s3-destination":{"lastAttemptAt":null,"lastAttemptLocalDate":null,"lastSuccessAt":null,"lastErrorAt":null,"lastErrorMessage":null,"lastUploadedFileName":null,"lastUploadedSizeBytes":null,"lastUploadedDestination":null},"fixture-webdav-destination":{"lastAttemptAt":null,"lastAttemptLocalDate":null,"lastSuccessAt":null,"lastErrorAt":null,"lastErrorMessage":null,"lastUploadedFileName":null,"lastUploadedSizeBytes":null,"lastUploadedDestination":null}}}
\.


--
-- Data for Name: devices; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.devices (user_id, device_identifier, name, type, session_stamp, encrypted_user_key, encrypted_public_key, encrypted_private_key, push_uuid, push_token, banned, banned_at, device_note, last_seen_at, created_at, updated_at) FROM stdin;
42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	90f4a140-2c18-42cd-8412-30e2c355befc	cli	25	f6a26773-04f4-4b6d-99f3-5c3c3a7fff15	\N	\N	\N	152327a7-954b-422f-ad03-8a80b2e02375	\N	0	\N	\N	2026-09-29T11:48:13.775Z	2026-09-29T11:48:13.775Z	2026-09-29T11:48:13.775Z
b47224e1-7541-4fed-8262-51a236e3f206	c51d72e8-0110-4bde-84b5-1938c8649ab7	cli	25	ea16ea25-a801-4d3f-869b-4e9946d9359e	\N	\N	\N	858c626b-707e-4c70-b11b-5a728a3fb127	\N	0	\N	\N	2026-09-29T11:48:14.322Z	2026-09-29T11:48:14.322Z	2026-09-29T11:48:14.322Z
19290199-ab15-4919-823c-38b084e4e827	c678062c-9a40-46ed-81d5-ddfa34f8be13	cli	25	4b4ca89d-8491-449c-b0fa-a8859215ab35	\N	\N	\N	b85a3663-1263-43dd-b59c-0887e0ee8247	\N	0	\N	\N	2026-09-29T11:48:14.334Z	2026-09-29T11:48:14.334Z	2026-09-29T11:48:14.334Z
f175fcfb-4094-43d5-9e98-b98725c0283a	37c1227c-4767-4178-8052-1d23f3b6faf7	cli	25	b35364e6-2ae2-4c19-a224-503b67c393cd	\N	\N	\N	db37c181-5755-4d95-842e-fea373165579	\N	0	\N	\N	2026-09-29T11:48:14.347Z	2026-09-29T11:48:14.347Z	2026-09-29T11:48:14.347Z
d65ed8ce-595f-4e68-b9dc-9c54f036a177	a68f14aa-6f05-4b23-878d-23b68e79e4d7	cli	25	0989485a-629e-452d-b525-6246f7de593d	\N	\N	\N	abcafd4a-9c11-48aa-93d1-e79e4bc06953	\N	0	\N	\N	2026-09-29T11:48:14.359Z	2026-09-29T11:48:14.359Z	2026-09-29T11:48:14.359Z
689390e4-7017-4751-b384-b34c8ef41116	86340e12-b069-4d87-8974-1f48770cf529	cli	25	6900c7a4-8745-4408-8148-eb172d625a36	\N	\N	\N	05912221-046c-4e8b-bd52-47be46fc97ac	\N	0	\N	\N	2026-09-29T11:48:14.370Z	2026-09-29T11:48:14.370Z	2026-09-29T11:48:14.370Z
032772a9-e7c1-4305-a14e-2ed1b3fef953	57183f3d-291b-4716-8d4e-e14e18c70c81	cli	25	d85a0584-a1af-4c7f-b5ec-7525d5bb3743	\N	\N	\N	9f5ba761-90c7-44cb-a5e1-af65b2da9a9b	\N	0	\N	\N	2026-09-29T11:48:14.382Z	2026-09-29T11:48:14.382Z	2026-09-29T11:48:14.382Z
9c97c610-d3f5-428b-b495-99d5d3a4d84c	96b43e06-536e-46c9-8b56-84c5c0e2406b	cli	25	9eb912eb-d00d-4649-b786-9b0f6819015f	\N	\N	\N	2ac3ea9f-8a36-4c92-95d2-4a10d74a2c4c	\N	0	\N	\N	2026-09-29T11:48:14.393Z	2026-09-29T11:48:14.393Z	2026-09-29T11:48:14.393Z
e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	40051e25-1a91-4de1-815d-3371a44f1a54	cli	25	a74fa4cb-294c-4fa3-b09d-1b4f33d6591d	\N	\N	\N	75a5bbcb-a162-47a6-ad73-39ab70ce86f9	\N	0	\N	\N	2026-09-29T11:48:14.404Z	2026-09-29T11:48:14.404Z	2026-09-29T11:48:14.404Z
8ac1796d-04aa-41bd-a31b-cb96118b4703	14de3d3f-e3f6-4649-89a0-b32e132e7e2c	cli	25	a6fd38f9-6ab9-4421-a771-1f2c7a05e284	\N	\N	\N	4fbb8c1b-29e2-4fb3-9418-26eb9b999c79	\N	0	\N	\N	2026-09-29T11:48:14.415Z	2026-09-29T11:48:14.415Z	2026-09-29T11:48:14.415Z
502e2390-384d-40f3-83b7-53bfc6ee882c	5a09e91f-fc23-477f-8e5a-a05f346f905d	cli	25	92d3762f-e9a4-448f-b9e1-68bd41f711d5	\N	\N	\N	0db902bf-ff67-4e5a-a0d8-8912348e3ab3	\N	0	\N	\N	2026-09-29T11:48:14.426Z	2026-09-29T11:48:14.426Z	2026-09-29T11:48:14.426Z
9fab75a7-a33b-412e-9dda-f934a392b545	4a506dd0-c5ac-4ba4-8748-ab39c7154af8	cli	25	4964906d-71ab-4475-ae2c-0e1ffe94f301	\N	\N	\N	1e8697c5-cfa6-418f-bf5b-add103c386e7	\N	0	\N	\N	2026-09-29T11:48:14.437Z	2026-09-29T11:48:14.437Z	2026-09-29T11:48:14.437Z
2f27b21a-74ea-4b1c-b826-824b5ef88fb6	ff8b4f9a-0fe2-4234-838d-49127e3c2cc9	cli	25	efd97afc-2499-4afc-943c-0e5b5b105aa2	\N	\N	\N	f0e2d405-ccea-48ec-91c8-07652f170182	\N	0	\N	\N	2026-09-29T11:48:14.448Z	2026-09-29T11:48:14.448Z	2026-09-29T11:48:14.448Z
ed0a4b85-9e53-4fe7-a547-f1c8c245df48	474f8111-04de-451d-84e6-c71d61e157f2	cli	25	d05221fd-5949-439f-8289-5eb3dc42d4c1	\N	\N	\N	79dfa2c4-8fd6-4216-9073-85adb5027171	\N	0	\N	\N	2026-09-29T11:48:14.459Z	2026-09-29T11:48:14.459Z	2026-09-29T11:48:14.459Z
39af72eb-5f25-4b45-8504-2e4d6c39bccd	1397c8e4-4edb-4f7e-89ed-a829f3e696f3	cli	25	0096b432-e01b-474d-ac31-bae2fffa1b4f	\N	\N	\N	85e08b1e-891d-4274-b22c-66bf8ff73a86	\N	0	\N	\N	2026-09-29T11:48:14.470Z	2026-09-29T11:48:14.470Z	2026-09-29T11:48:14.470Z
e730e934-1006-4550-a443-c12680cb0719	a17a767e-6909-414a-8c39-7eff67e55c79	cli	25	b4f32904-36ef-4d6e-99be-5eceb3e6ef28	\N	\N	\N	d69f20fb-3869-4449-b044-a623a5270040	\N	0	\N	\N	2026-09-29T11:48:14.481Z	2026-09-29T11:48:14.481Z	2026-09-29T11:48:14.481Z
205c22e9-ce26-4b35-8f23-ea29fa42d9f5	a9214f0e-2628-4236-88d4-7e076a09b160	cli	25	e95e37e9-82ac-4b5e-9897-84ab13fb24ed	\N	\N	\N	9e6966b5-c226-41b0-9562-2bf0e5e6c774	\N	0	\N	\N	2026-09-29T11:48:14.493Z	2026-09-29T11:48:14.493Z	2026-09-29T11:48:14.493Z
d26f24e9-e3ad-4228-a191-c250c7423afd	14e2c52a-f0de-4ae5-81e7-d65826905eab	cli	25	2ab130ea-7a71-41ec-abc2-01a19d131028	\N	\N	\N	22fa344c-f115-490d-a692-948d90790540	\N	0	\N	\N	2026-09-29T11:48:14.503Z	2026-09-29T11:48:14.503Z	2026-09-29T11:48:14.503Z
1e7bbf40-54d5-49f3-812e-6336f876a0cd	fdbc82df-e8b9-47bd-82ad-08d88c0ddf56	cli	25	26b9c6a7-1a7c-4aa1-b2a9-f1e4e5f9e17b	\N	\N	\N	65e89111-bdde-43bb-b813-2509096339de	\N	0	\N	\N	2026-09-29T11:48:14.514Z	2026-09-29T11:48:14.514Z	2026-09-29T11:48:14.514Z
b47224e1-7541-4fed-8262-51a236e3f206	98cbc6ce-0bf3-4f1b-8437-cfe4d28ab8f8	Pixel 9	0	c6e56d92-8b74-42b2-9b82-55d39ae9ee83	\N	\N	\N	1ffa97fe-a0ab-4e17-af5f-d4192eaa818f	fixture-fcm-push-token-0001	0	\N	\N	2026-09-29T11:48:14.579Z	2026-09-29T11:48:14.579Z	2026-09-29T11:48:14.582Z
b47224e1-7541-4fed-8262-51a236e3f206	d765ae6c-f4b8-4246-8fbe-bea276f17d8f	chrome	9	4d24b009-7968-4bb3-a708-fb9831ece97b	\N	\N	\N	2e45a36c-6a5a-4ddf-921c-dc238bae5a29	\N	0	\N	\N	2026-09-29T11:48:14.592Z	2026-09-29T11:48:14.592Z	2026-09-29T11:48:14.592Z
b47224e1-7541-4fed-8262-51a236e3f206	fbfb5e63-dc64-4c5c-80c6-0eea840e0880	chrome-extension	2	30f2e9b7-fc33-4b28-8035-b7d328cf6cf3	\N	\N	\N	53a626d4-ddb3-4434-9ace-5e8269c0ba8b	\N	0	\N	\N	2026-09-29T11:48:14.603Z	2026-09-29T11:48:14.603Z	2026-09-29T11:48:14.603Z
b47224e1-7541-4fed-8262-51a236e3f206	dc32bea1-1f41-4c00-8bc3-903c7c6f1e81	windows	6	2aa64c4d-dc6a-4a0b-ac55-35e522806f9e	4.cnNhLWRldmljZS11c2VyLWtleQ==	2.aXYtZGV2aWNlLXB1YmxpYy1rZXk=|Y3QtZGV2aWNlLXB1YmxpYy1rZXk=|bWFjLWRldmljZS1wdWJsaWMta2V5	2.aXYtZGV2aWNlLXByaXZhdGUta2V5|Y3QtZGV2aWNlLXByaXZhdGUta2V5|bWFjLWRldmljZS1wcml2YXRlLWtleQ==	b6e3e419-8a43-4f76-82c7-e535e5ce8426	\N	0	\N	Work laptop	2026-09-29T11:48:14.614Z	2026-09-29T11:48:14.614Z	2026-09-29T11:48:14.617Z
b47224e1-7541-4fed-8262-51a236e3f206	afe5ecf0-f170-4a80-8afe-3887d3779241	sdk	21	dfe77206-b208-4266-b033-fc0c5b70e78d	\N	\N	\N	6900b87f-92d2-4e04-aab6-d41af69df651	\N	0	\N	\N	2026-09-29T11:48:16.118Z	2026-09-29T11:48:16.118Z	2026-09-29T11:48:16.118Z
b47224e1-7541-4fed-8262-51a236e3f206	17992036-4808-42fe-881f-76735d1b4447	auth-request-device	9	0c088417-0038-4920-b7e4-c4928fc0a067	\N	\N	\N	9cc85814-23ab-4b79-94f8-b6d804a55cc6	\N	0	\N	\N	2026-09-29T11:48:16.157Z	2026-09-29T11:48:16.157Z	2026-09-29T11:48:16.157Z
f175fcfb-4094-43d5-9e98-b98725c0283a	d16c15e2-a6c0-460a-896e-2257b6931070	remembered	25	e6bc3ad0-b3f6-4426-afa0-d9892d0c9811	\N	\N	\N	80ff322c-5e5f-477b-8198-7299a55e3500	\N	0	\N	\N	2026-09-29T11:48:16.627Z	2026-09-29T11:48:16.627Z	2026-09-29T11:48:16.627Z
d65ed8ce-595f-4e68-b9dc-9c54f036a177	b947a09e-fe15-4652-8788-9182704c4002	otp	25	d82c0ce8-8f26-41c7-9bef-d46607883761	\N	\N	\N	29c71e6c-6920-42ef-aab7-ab04739eabfe	\N	0	\N	\N	2026-09-29T11:48:16.652Z	2026-09-29T11:48:16.652Z	2026-09-29T11:48:16.652Z
689390e4-7017-4751-b384-b34c8ef41116	483d1b5b-3004-42e7-8f27-f84aa8234728	remembered	25	37252fec-be1d-42f0-968d-4775d8365738	\N	\N	\N	29e0c055-c086-4daf-bca4-d95411cc596b	\N	0	\N	\N	2026-09-29T11:48:16.701Z	2026-09-29T11:48:16.701Z	2026-09-29T11:48:16.701Z
032772a9-e7c1-4305-a14e-2ed1b3fef953	761d7da7-1af8-4a38-84a9-721861298c52	passkey-login	9	75657b2e-78db-4f56-b57c-58dbb402b0e2	\N	\N	\N	b28699c8-4fdd-44be-8696-21d2efbad9f6	\N	0	\N	\N	2026-09-29T11:48:16.749Z	2026-09-29T11:48:16.749Z	2026-09-29T11:48:16.749Z
502e2390-384d-40f3-83b7-53bfc6ee882c	f6f3bb15-e022-4fab-80ae-a779cedc9ac4	legacy-fixture	25	5ef59d7e-b9f5-471f-ab53-d85e3c48da4a	\N	\N	\N	9969cdbb-e4aa-4967-b93f-c7d07c504547	\N	0	\N	\N	2026-09-29T11:48:32.875Z	2026-09-29T11:48:32.875Z	2026-09-29T11:48:32.875Z
9fab75a7-a33b-412e-9dda-f934a392b545	2a3ba310-7319-4acc-8f69-c3f7f9281f84	sdk	21	507dc5c3-4f2a-4e48-b727-223cbc0c6979	\N	\N	\N	1e73adc4-22bf-415e-8cfa-0145ed7c2384	\N	0	\N	\N	2026-09-29T11:48:32.899Z	2026-09-29T11:48:32.899Z	2026-09-29T11:48:32.899Z
ed0a4b85-9e53-4fe7-a547-f1c8c245df48	601f883a-3201-44c3-8f95-72462c9203bd	legacy-fixture	25	e4d714fa-4e6d-45a1-90b5-163d0ca3acf8	\N	\N	\N	5e149bdb-be63-473e-b823-1b735a049fac	\N	0	\N	\N	2026-09-29T11:48:32.971Z	2026-09-29T11:48:32.971Z	2026-09-29T11:48:32.971Z
39af72eb-5f25-4b45-8504-2e4d6c39bccd	034f057d-9e6e-4966-8c1a-2baeb063c723	legacy-fixture	25	b6897121-bee1-4ab7-aed0-3efcc58dbae2	\N	\N	\N	1fc82385-b0d3-4ee5-9e04-a903d37956bc	\N	0	\N	\N	2026-09-29T11:48:32.991Z	2026-09-29T11:48:32.991Z	2026-09-29T11:48:32.991Z
e730e934-1006-4550-a443-c12680cb0719	2cd6e79d-c400-4fc5-8202-f5fca5e1d846	legacy-fixture	25	a1a93186-68cc-463c-9b30-6d03323a1adf	\N	\N	\N	cfde2c09-89ec-4d18-953a-4be65845eb66	\N	0	\N	\N	2026-09-29T11:48:33.004Z	2026-09-29T11:48:33.004Z	2026-09-29T11:48:33.004Z
205c22e9-ce26-4b35-8f23-ea29fa42d9f5	fe2eabce-5487-4df7-8af9-497b7f60e4c1	legacy-fixture	25	25d9cbd4-76d9-43ee-8dea-242b79d4ce83	\N	\N	\N	f8ff871e-4b22-49f7-b21a-60fc7c7bf581	\N	0	\N	\N	2026-09-29T11:48:33.015Z	2026-09-29T11:48:33.015Z	2026-09-29T11:48:33.015Z
\.


--
-- Data for Name: domain_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.domain_settings (user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at) FROM stdin;
b47224e1-7541-4fed-8262-51a236e3f206	[["fixture-mirror.example","fixture.example"]]	[{"id":"custom:fixture-mirror.example|fixture.example:0","domains":["fixture.example","fixture-mirror.example"],"excluded":false},{"id":"custom:paused-mirror.example|paused.example:1","domains":["paused.example","paused-mirror.example"],"excluded":true}]	[2,3]	2026-09-29T11:48:16.041Z
2f27b21a-74ea-4b1c-b826-824b5ef88fb6	[["legacy.example","legacy-mirror.example"]]	[]	[]	2025-06-01T00:00:00.000Z
\.


--
-- Data for Name: folders; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.folders (id, user_id, name, created_at, updated_at) FROM stdin;
72b3055f-729c-45b7-8fc2-9f053d8a37fa	b47224e1-7541-4fed-8262-51a236e3f206	2.aXYtZm9sZGVyLXBlcnNvbmFs|Y3QtZm9sZGVyLXBlcnNvbmFs|bWFjLWZvbGRlci1wZXJzb25hbA==	2026-09-29T11:48:14.621Z	2026-09-29T11:48:14.621Z
36b2d31c-e6dc-4382-91b6-1c34359e23c0	b47224e1-7541-4fed-8262-51a236e3f206	2.aXYtZm9sZGVyLXdvcms=|Y3QtZm9sZGVyLXdvcms=|bWFjLWZvbGRlci13b3Jr	2026-09-29T11:48:14.623Z	2026-09-29T11:48:14.623Z
c721c7f4-8bea-4d6d-9fae-c62b80a7a20b	b47224e1-7541-4fed-8262-51a236e3f206	2.aXYtZm9sZGVyLWVtcHR5|Y3QtZm9sZGVyLWVtcHR5|bWFjLWZvbGRlci1lbXB0eQ==	2026-09-29T11:48:14.626Z	2026-09-29T11:48:14.626Z
33773829-d164-4936-a21f-47246739c775	f175fcfb-4094-43d5-9e98-b98725c0283a	2.aXYtZm9sZGVyLXRvdHAtb3JnLWl0ZW1z|Y3QtZm9sZGVyLXRvdHAtb3JnLWl0ZW1z|bWFjLWZvbGRlci10b3RwLW9yZy1pdGVtcw==	2026-09-29T11:48:16.528Z	2026-09-29T11:48:16.528Z
a2656d34-484f-4062-97fc-f1facabea164	1e7bbf40-54d5-49f3-812e-6336f876a0cd	2.aXYtbGVnYWN5LWNpcGhlci1mb2xkZXI=|Y3QtbGVnYWN5LWNpcGhlci1mb2xkZXI=|bWFjLWxlZ2FjeS1jaXBoZXItZm9sZGVy	2026-09-29T11:48:16.787Z	2026-09-29T11:48:16.787Z
\.


--
-- Data for Name: invites; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.invites (code, created_by, used_by, expires_at, status, created_at, updated_at) FROM stdin;
e5ff6ced57c7ff4414a979284247b539af767da0	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	b47224e1-7541-4fed-8262-51a236e3f206	2026-09-30T11:48:13.793Z	used	2026-09-29T11:48:13.793Z	2026-09-29T11:48:13.806Z
14a40368ca384e3514ad225273f94f83285433b0	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	19290199-ab15-4919-823c-38b084e4e827	2026-09-30T11:48:13.820Z	used	2026-09-29T11:48:13.820Z	2026-09-29T11:48:13.841Z
564afb40fc325fea126d2d9a65efc0ede0ac9575	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	f175fcfb-4094-43d5-9e98-b98725c0283a	2026-09-30T11:48:13.868Z	used	2026-09-29T11:48:13.868Z	2026-09-29T11:48:13.909Z
5bd205308b94bde7481f0654d94832d88a8334a8	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	d65ed8ce-595f-4e68-b9dc-9c54f036a177	2026-09-30T11:48:13.925Z	used	2026-09-29T11:48:13.925Z	2026-09-29T11:48:13.937Z
69e41a7d4565f38c21f7bdf26cdd16295de962bc	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	689390e4-7017-4751-b384-b34c8ef41116	2026-09-30T11:48:13.948Z	used	2026-09-29T11:48:13.948Z	2026-09-29T11:48:13.960Z
1615e7381faabd8f4ca26a69e82e0407098bae7b	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	032772a9-e7c1-4305-a14e-2ed1b3fef953	2026-09-30T11:48:13.971Z	used	2026-09-29T11:48:13.971Z	2026-09-29T11:48:13.982Z
a1d221dec08845060c482853d16f2ab065ee5794	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	9c97c610-d3f5-428b-b495-99d5d3a4d84c	2026-09-30T11:48:13.992Z	used	2026-09-29T11:48:13.992Z	2026-09-29T11:48:14.004Z
3092b3bcb0a19fc79626fbe311c30a7ca85c5ec2	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	2026-09-30T11:48:14.018Z	used	2026-09-29T11:48:14.018Z	2026-09-29T11:48:14.036Z
684c1d38c285d41b24f78836f31c3bd44012caa0	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	8ac1796d-04aa-41bd-a31b-cb96118b4703	2026-09-30T11:48:14.052Z	used	2026-09-29T11:48:14.052Z	2026-09-29T11:48:14.065Z
ccf7d11fd909e456f15dbbca89f612004d0b8e0c	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	502e2390-384d-40f3-83b7-53bfc6ee882c	2026-09-30T11:48:14.078Z	used	2026-09-29T11:48:14.078Z	2026-09-29T11:48:14.093Z
d208e3de77bf1bf6331882b25fa8efd9c40126ae	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	9fab75a7-a33b-412e-9dda-f934a392b545	2026-09-30T11:48:14.109Z	used	2026-09-29T11:48:14.109Z	2026-09-29T11:48:14.135Z
00744f1a988515fad0bcc93c20565c39c56fe0f8	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2f27b21a-74ea-4b1c-b826-824b5ef88fb6	2026-09-30T11:48:14.148Z	used	2026-09-29T11:48:14.148Z	2026-09-29T11:48:14.162Z
1c66a24a7800b716a8eb1673cc906b443a1d0768	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	2026-09-30T11:48:14.177Z	used	2026-09-29T11:48:14.177Z	2026-09-29T11:48:14.189Z
bba188364de7ee392a38edf94a0c8884803392d5	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	39af72eb-5f25-4b45-8504-2e4d6c39bccd	2026-09-30T11:48:14.199Z	used	2026-09-29T11:48:14.199Z	2026-09-29T11:48:14.211Z
e504cdfb253c4f187e503983b69f33bddc8b2fcc	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	e730e934-1006-4550-a443-c12680cb0719	2026-09-30T11:48:14.221Z	used	2026-09-29T11:48:14.221Z	2026-09-29T11:48:14.232Z
7fa2ba8ba57ee2cd78779e459b1ab3cf6d5213ed	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	2026-09-30T11:48:14.242Z	used	2026-09-29T11:48:14.242Z	2026-09-29T11:48:14.254Z
d49e18f2b6e059d500e04f53fe84bfdb4b17d1ce	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	d26f24e9-e3ad-4228-a191-c250c7423afd	2026-09-30T11:48:14.265Z	used	2026-09-29T11:48:14.265Z	2026-09-29T11:48:14.277Z
23ae762a5bd3eccb79e5df08de6f35ebec762f4f	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	1e7bbf40-54d5-49f3-812e-6336f876a0cd	2026-09-30T11:48:14.291Z	used	2026-09-29T11:48:14.291Z	2026-09-29T11:48:14.307Z
92a69ff0eb8a03a0431a1d181e3f8f31f206d8a3	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	2099-01-01T00:00:00.000Z	active	2026-09-29T11:48:14.538Z	2026-09-29T11:48:14.538Z
799d07a40d800a8aa8a6a0dd8af03f3168a0c804	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	\N	2020-01-01T00:00:00.000Z	active	2026-09-29T11:48:14.547Z	2026-09-29T11:48:14.547Z
\.


--
-- Data for Name: login_attempts_ip; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.login_attempts_ip (ip, attempts, locked_until, updated_at) FROM stdin;
\.


--
-- Data for Name: org_memberships; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.org_memberships (id, org_id, user_id, status, type, access_all, akey, revoked_status, invited_by, created_at, updated_at) FROM stdin;
b2367faf-9c0e-4784-8530-bcb037ad8581	4978de20-9a02-4877-a193-048eaa0d30ce	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2	0	1	4.cnNhLW9yZy1rZXktYWRtaW4=	\N	\N	2026-09-29T11:48:16.162Z	2026-09-29T11:48:16.162Z
f63f83a8-a800-497a-9cec-a6ef434748c3	4978de20-9a02-4877-a193-048eaa0d30ce	d65ed8ce-595f-4e68-b9dc-9c54f036a177	0	2	0	\N	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.235Z	2026-09-29T11:48:16.235Z
15c8746d-6e66-4f6e-8515-aaab77516f4d	4978de20-9a02-4877-a193-048eaa0d30ce	689390e4-7017-4751-b384-b34c8ef41116	1	2	0	\N	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.246Z	2026-09-29T11:48:16.275Z
66fdeb57-88dd-46d2-b003-253c43aa3f46	4978de20-9a02-4877-a193-048eaa0d30ce	19290199-ab15-4919-823c-38b084e4e827	2	1	1	4.cnNhLW9yZy1rZXktYXJnb24=	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.189Z	2026-09-29T11:48:16.283Z
71e73581-d6b4-4f1f-a056-2d5cc59fabc4	4978de20-9a02-4877-a193-048eaa0d30ce	b47224e1-7541-4fed-8262-51a236e3f206	2	2	0	4.cnNhLW9yZy1rZXktdmF1bHQ=	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.199Z	2026-09-29T11:48:16.288Z
c04561f1-e4f6-4593-8934-22d7184f1590	4978de20-9a02-4877-a193-048eaa0d30ce	f175fcfb-4094-43d5-9e98-b98725c0283a	2	2	0	4.cnNhLW9yZy1rZXktdG90cA==	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.209Z	2026-09-29T11:48:16.293Z
a528efc7-6194-4ace-a74c-bbc0d1b9aa56	4978de20-9a02-4877-a193-048eaa0d30ce	9c97c610-d3f5-428b-b495-99d5d3a4d84c	2	3	0	4.cnNhLW9yZy1rZXktbWFuYWdlcg==	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.218Z	2026-09-29T11:48:16.300Z
b4ec4c6d-f1fe-443f-8d32-db46cdd3e714	4978de20-9a02-4877-a193-048eaa0d30ce	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	2	3	1	4.cnNhLW9yZy1rZXktY3VzdG9t	\N	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.224Z	2026-09-29T11:48:16.311Z
d92349eb-d8a5-4289-9adb-cd3ca7c03173	4978de20-9a02-4877-a193-048eaa0d30ce	032772a9-e7c1-4305-a14e-2ed1b3fef953	-1	2	0	4.cnNhLW9yZy1rZXktcGFzc2tleQ==	2	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.255Z	2026-09-29T11:48:16.345Z
9548b523-4991-4a01-be7b-3916744ab29d	844847a4-f6fd-4267-9990-b8eba5516b49	19290199-ab15-4919-823c-38b084e4e827	2	0	1	4.cnNhLW9yZzIta2V5LWFyZ29u	\N	\N	2026-09-29T11:48:16.551Z	2026-09-29T11:48:16.551Z
\.


--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.organizations (id, name, billing_email, public_key, private_key, created_at, updated_at) FROM stdin;
4978de20-9a02-4877-a193-048eaa0d30ce	Fixture Org	admin@fixture.example	Zml4dHVyZS1vcmctcHVibGlj	2.aXYtZml4dHVyZS1vcmctcHJpdmF0ZQ==|Y3QtZml4dHVyZS1vcmctcHJpdmF0ZQ==|bWFjLWZpeHR1cmUtb3JnLXByaXZhdGU=	2026-09-29T11:48:16.162Z	2026-09-29T11:48:16.162Z
844847a4-f6fd-4267-9990-b8eba5516b49	Argon Org	argon@fixture.example	\N	\N	2026-09-29T11:48:16.551Z	2026-09-29T11:48:16.551Z
\.


--
-- Data for Name: rate_limit_buckets; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.rate_limit_buckets (bucket_key, count, expires_at, updated_at) FROM stdin;
\.


--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.refresh_tokens (token, user_id, expires_at, device_identifier, device_session_stamp, security_stamp, created_at, last_used_at, absolute_expires_at, client_type) FROM stdin;
sha256:c81e592b6b666bad69043f30bdfba29058010df30bbc805bc701fcc119b743e8	42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	4070908800000	90f4a140-2c18-42cd-8412-30e2c355befc	f6a26773-04f4-4b6d-99f3-5c3c3a7fff15	6be22168-c4eb-4347-96f0-43b51cc9baf6	1790682493776	1790682493776	4070908800000	cli
sha256:9d1c740474480242faedc8139b4af1def6e27b5d1f05a7ae6edaef2837cfe93d	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	c51d72e8-0110-4bde-84b5-1938c8649ab7	ea16ea25-a801-4d3f-869b-4e9946d9359e	94821132-03dd-446c-9dfe-fa442cd600b7	1790682494323	1790682494323	4070908800000	cli
sha256:ed56eeb1fb2cbaf588e81fb8e08c4007debb5cb5549b8cd93d4d9100ede0e814	9fab75a7-a33b-412e-9dda-f934a392b545	4070908800000	2a3ba310-7319-4acc-8f69-c3f7f9281f84	507dc5c3-4f2a-4e48-b727-223cbc0c6979	b0858aed-7227-4b60-92db-9132e79bf65d	1790682512905	1790682512905	4070908800000	user.9fab75a7-a33b-412e-9dda-f934a392b545
sha256:cd0913e0d328e9370fb3d58a033264ff5c6583de0c713df2b02b04046ef54a4d	19290199-ab15-4919-823c-38b084e4e827	4070908800000	c678062c-9a40-46ed-81d5-ddfa34f8be13	4b4ca89d-8491-449c-b0fa-a8859215ab35	f315821b-41c1-4c77-9aa7-55ac35a7f76c	1790682494335	1790682494335	4070908800000	cli
sha256:b61235f2cd93c4b5919764146ce25d551ba0c977598dbcefbc0141953538d0ee	032772a9-e7c1-4305-a14e-2ed1b3fef953	4070908800000	57183f3d-291b-4716-8d4e-e14e18c70c81	d85a0584-a1af-4c7f-b5ec-7525d5bb3743	fd107a09-2b65-40f4-b127-f46dbf452b38	1790682494382	1790682494382	4070908800000	cli
sha256:d1d00a47b0d3a98aaddabd9a2bd06bd67842215e22964ad60bce2f85650284a9	9c97c610-d3f5-428b-b495-99d5d3a4d84c	4070908800000	96b43e06-536e-46c9-8b56-84c5c0e2406b	9eb912eb-d00d-4649-b786-9b0f6819015f	a15401fc-0c6a-4dfa-abd4-7b259140a9b5	1790682494394	1790682494394	4070908800000	cli
sha256:4a718c4f83cfa11fe4d171bb5cf62d36b4d3d0495398f9b1c13f806ce3a5370e	e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	4070908800000	40051e25-1a91-4de1-815d-3371a44f1a54	a74fa4cb-294c-4fa3-b09d-1b4f33d6591d	1d82103d-3e06-4da8-b9f5-a19ded3aa880	1790682494405	1790682494405	4070908800000	cli
sha256:544cd5e6140704f21a88e1c02b82089a75d99e96b330c850bb133ffec9a797fa	d26f24e9-e3ad-4228-a191-c250c7423afd	4070908800000	\N	\N	\N	\N	\N	\N	\N
sha256:f7a47338300bae28d6fc415fb1c0f5577edffe435d6f5f831fb3b49258a70140	502e2390-384d-40f3-83b7-53bfc6ee882c	4070908800000	5a09e91f-fc23-477f-8e5a-a05f346f905d	92d3762f-e9a4-448f-b9e1-68bd41f711d5	c7c02ddc-21b7-43cc-a551-09f7e5d6f39e	1790682494427	1790682494427	4070908800000	cli
sha256:166103849dfd86882577105b5067dd91a5c14bafc61d4e772c208b029796a39a	9fab75a7-a33b-412e-9dda-f934a392b545	4070908800000	4a506dd0-c5ac-4ba4-8748-ab39c7154af8	4964906d-71ab-4475-ae2c-0e1ffe94f301	b0858aed-7227-4b60-92db-9132e79bf65d	1790682494438	1790682494438	4070908800000	cli
sha256:309433627a65f706f22072f790ad32a0784e9d202f6a1b571febed9497c52049	2f27b21a-74ea-4b1c-b826-824b5ef88fb6	4070908800000	ff8b4f9a-0fe2-4234-838d-49127e3c2cc9	efd97afc-2499-4afc-943c-0e5b5b105aa2	79076968-a13d-4ba3-9cc5-25715f91a9f6	1790682494449	1790682494449	4070908800000	cli
sha256:6e05787f0f547177e420b774fd0b9d9f68d29a708c0eae26340befc7a4657866	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	4070908800000	474f8111-04de-451d-84e6-c71d61e157f2	d05221fd-5949-439f-8289-5eb3dc42d4c1	f04e012e-41db-465b-9854-436e7243b386	1790682494460	1790682494460	4070908800000	cli
sha256:7e543013570789f867fa76c7e2d47c4c28793ce178ebbf942ff97bf6440291df	39af72eb-5f25-4b45-8504-2e4d6c39bccd	4070908800000	1397c8e4-4edb-4f7e-89ed-a829f3e696f3	0096b432-e01b-474d-ac31-bae2fffa1b4f	a00eb6cc-2b4d-4617-9965-4d22bbf95ce1	1790682494471	1790682494471	4070908800000	cli
sha256:9ac07aa3349ee779808818181b61f6e771bf197ffbc4d3e5a0d7ecfd9c1ddc16	e730e934-1006-4550-a443-c12680cb0719	4070908800000	a17a767e-6909-414a-8c39-7eff67e55c79	b4f32904-36ef-4d6e-99be-5eceb3e6ef28	8f02eec0-7cd0-4b11-9212-592c3b40860d	1790682494482	1790682494482	4070908800000	cli
sha256:ef8f9e0c0681aa1fb11ea058e0ea6b0316ade74174edaa1c1a7eaede26263ecc	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	4070908800000	a9214f0e-2628-4236-88d4-7e076a09b160	e95e37e9-82ac-4b5e-9897-84ab13fb24ed	1e961452-c0b6-47b0-83c8-69b52493410b	1790682494493	1790682494493	4070908800000	cli
sha256:5adb4ff479f587452fb472212896f2fd33fed1b22834f2673e7b8113688cb41c	1e7bbf40-54d5-49f3-812e-6336f876a0cd	4070908800000	fdbc82df-e8b9-47bd-82ad-08d88c0ddf56	26b9c6a7-1a7c-4aa1-b2a9-f1e4e5f9e17b	ad5fb3e5-0fdd-4fc7-889c-404e9d74ca4f	1790682494515	1790682494515	4070908800000	cli
sha256:90c3fc5b2bd0e07f10f9ece14a8bf6e9638dbe94bde6d829e9f0a650c031a38b	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	98cbc6ce-0bf3-4f1b-8437-cfe4d28ab8f8	c6e56d92-8b74-42b2-9b82-55d39ae9ee83	94821132-03dd-446c-9dfe-fa442cd600b7	1790682494579	1790682494579	4070908800000	mobile
sha256:ca4f0d7af44d5f89ec753c57f2eef9b8e647a376d2b48eb5f30bf53868f8c95d	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	d765ae6c-f4b8-4246-8fbe-bea276f17d8f	4d24b009-7968-4bb3-a708-fb9831ece97b	94821132-03dd-446c-9dfe-fa442cd600b7	1790682494592	1790682494592	4070908800000	web
sha256:e52bc4a6a85f8a31af8820bb5b255c7e9b94afd2afef75a5fbb1da2cbaeb9790	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	fbfb5e63-dc64-4c5c-80c6-0eea840e0880	30f2e9b7-fc33-4b28-8035-b7d328cf6cf3	94821132-03dd-446c-9dfe-fa442cd600b7	1790682494604	1790682494604	4070908800000	browser
sha256:1d028cd57a0ef6475857c132257a7d3d70f6d2d101ad25cebecf993027b8f046	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	dc32bea1-1f41-4c00-8bc3-903c7c6f1e81	2aa64c4d-dc6a-4a0b-ac55-35e522806f9e	94821132-03dd-446c-9dfe-fa442cd600b7	1790682494615	1790682494615	4070908800000	desktop
sha256:9f913d974465b27a5907d8c404a66fbd4ea1f73ce75bea92509752acee409b27	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	afe5ecf0-f170-4a80-8afe-3887d3779241	dfe77206-b208-4266-b033-fc0c5b70e78d	94821132-03dd-446c-9dfe-fa442cd600b7	1790682496120	1790682496120	4070908800000	user.b47224e1-7541-4fed-8262-51a236e3f206
sha256:dc075f2f86c64b5ff69fcaa9a3762fa3afe8570b0d4840f7268e0f7003f277bc	b47224e1-7541-4fed-8262-51a236e3f206	4070908800000	17992036-4808-42fe-881f-76735d1b4447	0c088417-0038-4920-b7e4-c4928fc0a067	94821132-03dd-446c-9dfe-fa442cd600b7	1790682496159	1790682496159	4070908800000	web
sha256:69bcb060b45df6299bb1691e2251149220973170921208158b4a2a373f01a226	f175fcfb-4094-43d5-9e98-b98725c0283a	4070908800000	d16c15e2-a6c0-460a-896e-2257b6931070	e6bc3ad0-b3f6-4426-afa0-d9892d0c9811	02209a72-96d1-476f-81cc-d62c9466a294	1790682496628	1790682496628	4070908800000	cli
sha256:c46f41a45b0292c2f39f66bf601b432abd01d4039275ac15937d5accfd41ea6b	d65ed8ce-595f-4e68-b9dc-9c54f036a177	4070908800000	b947a09e-fe15-4652-8788-9182704c4002	d82c0ce8-8f26-41c7-9bef-d46607883761	8cfeb911-ecf4-4397-8654-d9ce6bdc8722	1790682496653	1790682496653	4070908800000	cli
sha256:8a0172c90f1a9c1b9ef2720558297ac49368a89695979f64554a8bfa2c563429	ed0a4b85-9e53-4fe7-a547-f1c8c245df48	4070908800000	601f883a-3201-44c3-8f95-72462c9203bd	e4d714fa-4e6d-45a1-90b5-163d0ca3acf8	f04e012e-41db-465b-9854-436e7243b386	1790682512973	1790682512973	4070908800000	cli
sha256:ae82d02f35ef9a45f9d2520822b015c2f2f092127c350c25d4cd5f0459841755	689390e4-7017-4751-b384-b34c8ef41116	4070908800000	483d1b5b-3004-42e7-8f27-f84aa8234728	37252fec-be1d-42f0-968d-4775d8365738	12cf3157-93f1-42d3-a42c-4e13002c1d6e	1790682496701	1790682496701	4070908800000	cli
sha256:06209d050b2a90cc227db121608c10958e65075d05b75d9d55e07683e2149579	032772a9-e7c1-4305-a14e-2ed1b3fef953	4070908800000	761d7da7-1af8-4a38-84a9-721861298c52	75657b2e-78db-4f56-b57c-58dbb402b0e2	fd107a09-2b65-40f4-b127-f46dbf452b38	1790682496750	1790682496750	4070908800000	web
sha256:2049434c10884bce433b9eed7e31b2adeaf660fbeca5f84352efe12882b348e3	502e2390-384d-40f3-83b7-53bfc6ee882c	4070908800000	f6f3bb15-e022-4fab-80ae-a779cedc9ac4	5ef59d7e-b9f5-471f-ab53-d85e3c48da4a	c7c02ddc-21b7-43cc-a551-09f7e5d6f39e	1790682512883	1790682512883	4070908800000	cli
sha256:34b994aa13ae623fb2ae277b55d54829a4e5039032413e51efd17488387bc16e	39af72eb-5f25-4b45-8504-2e4d6c39bccd	4070908800000	034f057d-9e6e-4966-8c1a-2baeb063c723	b6897121-bee1-4ab7-aed0-3efcc58dbae2	a00eb6cc-2b4d-4617-9965-4d22bbf95ce1	1790682512992	1790682512992	4070908800000	cli
sha256:f66d61b4b505a0b295528e8a199b81ecfff00fea50cffdbd256b782863e24d46	e730e934-1006-4550-a443-c12680cb0719	4070908800000	2cd6e79d-c400-4fc5-8202-f5fca5e1d846	a1a93186-68cc-463c-9b30-6d03323a1adf	8f02eec0-7cd0-4b11-9212-592c3b40860d	1790682513005	1790682513005	4070908800000	cli
sha256:918edaefd8a0325d2134609a76954006d30445057c632b37283b2d561de5120b	205c22e9-ce26-4b35-8f23-ea29fa42d9f5	4070908800000	fe2eabce-5487-4df7-8af9-497b7f60e4c1	25d9cbd4-76d9-43ee-8dea-242b79d4ce83	1e961452-c0b6-47b0-83c8-69b52493410b	1790682513016	1790682513016	4070908800000	cli
\.


--
-- Data for Name: sends; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sends (id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date) FROM stdin;
67108e1a-7854-4cb8-8de8-0e6dc4375161	b47224e1-7541-4fed-8262-51a236e3f206	0	2.aXYtc2VuZC1uYW1lLXRleHQtYWNjZXNzZWQ=|Y3Qtc2VuZC1uYW1lLXRleHQtYWNjZXNzZWQ=|bWFjLXNlbmQtbmFtZS10ZXh0LWFjY2Vzc2Vk	2.aXYtc2VuZC1ub3Rlcy10ZXh0LWFjY2Vzc2Vk|Y3Qtc2VuZC1ub3Rlcy10ZXh0LWFjY2Vzc2Vk|bWFjLXNlbmQtbm90ZXMtdGV4dC1hY2Nlc3NlZA==	{"text":"2.aXYtc2VuZC10ZXh0LXRleHQtYWNjZXNzZWQ=|Y3Qtc2VuZC10ZXh0LXRleHQtYWNjZXNzZWQ=|bWFjLXNlbmQtdGV4dC10ZXh0LWFjY2Vzc2Vk","hidden":false}	2.aXYtc2VuZC1rZXktdGV4dC1hY2Nlc3NlZA==|Y3Qtc2VuZC1rZXktdGV4dC1hY2Nlc3NlZA==|bWFjLXNlbmQta2V5LXRleHQtYWNjZXNzZWQ=	\N	\N	\N	2	\N	10	2	0	0	2026-09-29T11:48:15.905Z	2026-09-29T11:48:15.936Z	\N	2099-01-01T00:00:00.000Z
7978b4c8-a6c5-447e-a11d-6677f3f0bd7a	b47224e1-7541-4fed-8262-51a236e3f206	0	2.aXYtc2VuZC1uYW1lLXRleHQtcGFzc3dvcmQ=|Y3Qtc2VuZC1uYW1lLXRleHQtcGFzc3dvcmQ=|bWFjLXNlbmQtbmFtZS10ZXh0LXBhc3N3b3Jk	2.aXYtc2VuZC1ub3Rlcy10ZXh0LXBhc3N3b3Jk|Y3Qtc2VuZC1ub3Rlcy10ZXh0LXBhc3N3b3Jk|bWFjLXNlbmQtbm90ZXMtdGV4dC1wYXNzd29yZA==	{"text":"2.aXYtc2VuZC10ZXh0LXRleHQtcGFzc3dvcmQ=|Y3Qtc2VuZC10ZXh0LXRleHQtcGFzc3dvcmQ=|bWFjLXNlbmQtdGV4dC10ZXh0LXBhc3N3b3Jk","hidden":false}	2.aXYtc2VuZC1rZXktdGV4dC1wYXNzd29yZA==|Y3Qtc2VuZC1rZXktdGV4dC1wYXNzd29yZA==|bWFjLXNlbmQta2V5LXRleHQtcGFzc3dvcmQ=	c2VuZC1wYXNzd29yZCMjIyMjIyMjIyMjIyMjIyMjIyM=	\N	\N	1	\N	\N	0	0	0	2026-09-29T11:48:15.949Z	2026-09-29T11:48:15.949Z	\N	2099-01-01T00:00:00.000Z
38c3b624-c979-40d9-a3e7-fe3a59fa505c	b47224e1-7541-4fed-8262-51a236e3f206	0	2.aXYtc2VuZC1uYW1lLXRleHQtcGFzc3dvcmQtc2VydmVyLWhhc2hlZA==|Y3Qtc2VuZC1uYW1lLXRleHQtcGFzc3dvcmQtc2VydmVyLWhhc2hlZA==|bWFjLXNlbmQtbmFtZS10ZXh0LXBhc3N3b3JkLXNlcnZlci1oYXNoZWQ=	2.aXYtc2VuZC1ub3Rlcy10ZXh0LXBhc3N3b3JkLXNlcnZlci1oYXNoZWQ=|Y3Qtc2VuZC1ub3Rlcy10ZXh0LXBhc3N3b3JkLXNlcnZlci1oYXNoZWQ=|bWFjLXNlbmQtbm90ZXMtdGV4dC1wYXNzd29yZC1zZXJ2ZXItaGFzaGVk	{"text":"2.aXYtc2VuZC10ZXh0LXRleHQtcGFzc3dvcmQtc2VydmVyLWhhc2hlZA==|Y3Qtc2VuZC10ZXh0LXRleHQtcGFzc3dvcmQtc2VydmVyLWhhc2hlZA==|bWFjLXNlbmQtdGV4dC10ZXh0LXBhc3N3b3JkLXNlcnZlci1oYXNoZWQ=","hidden":false}	2.aXYtc2VuZC1rZXktdGV4dC1wYXNzd29yZC1zZXJ2ZXItaGFzaGVk|Y3Qtc2VuZC1rZXktdGV4dC1wYXNzd29yZC1zZXJ2ZXItaGFzaGVk|bWFjLXNlbmQta2V5LXRleHQtcGFzc3dvcmQtc2VydmVyLWhhc2hlZA==	GB6bBbjZYgUe234NvYtePplVhDolO7fFTzjbVIfev8w	nJq1y-0xFr4wMggTiP2NPj2qHCtJoUqW8dAl9bIBTUX9W_l9dzWjx5HQBYAWtJ0C2ysHi9CmYUwo_ngNB-JkAw	100000	1	\N	\N	0	0	0	2026-09-29T11:48:15.959Z	2026-09-29T11:48:15.959Z	\N	2099-01-01T00:00:00.000Z
2cb5b7a4-5a64-47ac-b1c7-007cbad7b490	b47224e1-7541-4fed-8262-51a236e3f206	0	2.aXYtc2VuZC1uYW1lLXRleHQtZGlzYWJsZWQ=|Y3Qtc2VuZC1uYW1lLXRleHQtZGlzYWJsZWQ=|bWFjLXNlbmQtbmFtZS10ZXh0LWRpc2FibGVk	2.aXYtc2VuZC1ub3Rlcy10ZXh0LWRpc2FibGVk|Y3Qtc2VuZC1ub3Rlcy10ZXh0LWRpc2FibGVk|bWFjLXNlbmQtbm90ZXMtdGV4dC1kaXNhYmxlZA==	{"text":"2.aXYtc2VuZC10ZXh0LXRleHQtZGlzYWJsZWQ=|Y3Qtc2VuZC10ZXh0LXRleHQtZGlzYWJsZWQ=|bWFjLXNlbmQtdGV4dC10ZXh0LWRpc2FibGVk","hidden":false}	2.aXYtc2VuZC1rZXktdGV4dC1kaXNhYmxlZA==|Y3Qtc2VuZC1rZXktdGV4dC1kaXNhYmxlZA==|bWFjLXNlbmQta2V5LXRleHQtZGlzYWJsZWQ=	\N	\N	\N	2	\N	\N	0	1	0	2026-09-29T11:48:15.989Z	2026-09-29T11:48:15.989Z	\N	2099-01-01T00:00:00.000Z
f8a5f3c0-c962-456d-a10e-ce5c147fbd03	b47224e1-7541-4fed-8262-51a236e3f206	0	2.aXYtc2VuZC1uYW1lLXRleHQtbWF4LWFjY2Vzcy1yZWFjaGVk|Y3Qtc2VuZC1uYW1lLXRleHQtbWF4LWFjY2Vzcy1yZWFjaGVk|bWFjLXNlbmQtbmFtZS10ZXh0LW1heC1hY2Nlc3MtcmVhY2hlZA==	2.aXYtc2VuZC1ub3Rlcy10ZXh0LW1heC1hY2Nlc3MtcmVhY2hlZA==|Y3Qtc2VuZC1ub3Rlcy10ZXh0LW1heC1hY2Nlc3MtcmVhY2hlZA==|bWFjLXNlbmQtbm90ZXMtdGV4dC1tYXgtYWNjZXNzLXJlYWNoZWQ=	{"text":"2.aXYtc2VuZC10ZXh0LXRleHQtbWF4LWFjY2Vzcy1yZWFjaGVk|Y3Qtc2VuZC10ZXh0LXRleHQtbWF4LWFjY2Vzcy1yZWFjaGVk|bWFjLXNlbmQtdGV4dC10ZXh0LW1heC1hY2Nlc3MtcmVhY2hlZA==","hidden":false}	2.aXYtc2VuZC1rZXktdGV4dC1tYXgtYWNjZXNzLXJlYWNoZWQ=|Y3Qtc2VuZC1rZXktdGV4dC1tYXgtYWNjZXNzLXJlYWNoZWQ=|bWFjLXNlbmQta2V5LXRleHQtbWF4LWFjY2Vzcy1yZWFjaGVk	\N	\N	\N	2	\N	1	1	0	0	2026-09-29T11:48:15.991Z	2026-09-29T11:48:15.993Z	\N	2099-01-01T00:00:00.000Z
a0b4052e-3530-44e9-8342-d992a3b7c119	b47224e1-7541-4fed-8262-51a236e3f206	1	2.aXYtc2VuZC1uYW1lLWZpbGU=|Y3Qtc2VuZC1uYW1lLWZpbGU=|bWFjLXNlbmQtbmFtZS1maWxl	\N	{"fileName":"2.aXYtc2VuZC1maWxlLW5hbWU=|Y3Qtc2VuZC1maWxlLW5hbWU=|bWFjLXNlbmQtZmlsZS1uYW1l","id":"c376f82c-82e0-4e5f-bb66-7a23b0a7bee7","size":520,"sizeName":"520 Bytes"}	2.aXYtc2VuZC1rZXktZmlsZQ==|Y3Qtc2VuZC1rZXktZmlsZQ==|bWFjLXNlbmQta2V5LWZpbGU=	\N	\N	\N	2	\N	5	1	0	0	2026-09-29T11:48:15.996Z	2026-09-29T11:48:16.012Z	\N	2099-01-01T00:00:00.000Z
4f14072f-c634-4326-852c-4322d624947a	b47224e1-7541-4fed-8262-51a236e3f206	0	2.aXYtc2VuZC1uYW1lLXRleHQtaGlkZGVuLWhpZGUtZW1haWwtZXhwaXJpbmc=|Y3Qtc2VuZC1uYW1lLXRleHQtaGlkZGVuLWhpZGUtZW1haWwtZXhwaXJpbmc=|bWFjLXNlbmQtbmFtZS10ZXh0LWhpZGRlbi1oaWRlLWVtYWlsLWV4cGlyaW5n	2.aXYtc2VuZC1ub3Rlcy10ZXh0LWhpZGRlbi1oaWRlLWVtYWlsLWV4cGlyaW5n|Y3Qtc2VuZC1ub3Rlcy10ZXh0LWhpZGRlbi1oaWRlLWVtYWlsLWV4cGlyaW5n|bWFjLXNlbmQtbm90ZXMtdGV4dC1oaWRkZW4taGlkZS1lbWFpbC1leHBpcmluZw==	{"text":"2.aXYtc2VuZC10ZXh0LWhpZGRlbg==|Y3Qtc2VuZC10ZXh0LWhpZGRlbg==|bWFjLXNlbmQtdGV4dC1oaWRkZW4=","hidden":true}	2.aXYtc2VuZC1rZXktdGV4dC1oaWRkZW4taGlkZS1lbWFpbC1leHBpcmluZw==|Y3Qtc2VuZC1rZXktdGV4dC1oaWRkZW4taGlkZS1lbWFpbC1leHBpcmluZw==|bWFjLXNlbmQta2V5LXRleHQtaGlkZGVuLWhpZGUtZW1haWwtZXhwaXJpbmc=	\N	\N	\N	2	\N	\N	0	0	1	2026-09-29T11:48:15.987Z	2026-09-29T11:48:15.987Z	2098-12-31T00:00:00.000Z	2099-01-01T00:00:00.000Z
\.


--
-- Data for Name: totp_login_replays; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.totp_login_replays (user_id, time_counter, consumed_at) FROM stdin;
f175fcfb-4094-43d5-9e98-b98725c0283a	59689417	1790682496596
f175fcfb-4094-43d5-9e98-b98725c0283a	59689416	1790682496626
ed0a4b85-9e53-4fe7-a547-f1c8c245df48	59689418	1790682512970
\.


--
-- Data for Name: trusted_two_factor_device_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.trusted_two_factor_device_tokens (token, user_id, device_identifier, expires_at) FROM stdin;
sha256:0b13ce0511e821472eea993ad28683c2e31ae98ba8cc6e485038a95ef3b92380	f175fcfb-4094-43d5-9e98-b98725c0283a	d16c15e2-a6c0-460a-896e-2257b6931070	4070908800000
sha256:3752cbca2d11f2483d45de051ba324aa9214f346e578223e20f95cd1cb957296	689390e4-7017-4751-b384-b34c8ef41116	483d1b5b-3004-42e7-8f27-f84aa8234728	4070908800000
\.


--
-- Data for Name: used_attachment_download_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.used_attachment_download_tokens (jti, expires_at) FROM stdin;
send:Pdg2QNERbUIwyFMu3Fpv2WxNpCZaXANIIk5dOYX8ewA	1790682796000
\.


--
-- Data for Name: user_revisions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_revisions (user_id, revision_date) FROM stdin;
f175fcfb-4094-43d5-9e98-b98725c0283a	2026-09-29T11:48:16.542Z
b47224e1-7541-4fed-8262-51a236e3f206	2026-09-29T11:48:16.548Z
19290199-ab15-4919-823c-38b084e4e827	2026-09-29T11:48:16.564Z
032772a9-e7c1-4305-a14e-2ed1b3fef953	2026-09-29T11:48:16.346Z
1e7bbf40-54d5-49f3-812e-6336f876a0cd	2026-09-29T11:48:16.797Z
502e2390-384d-40f3-83b7-53bfc6ee882c	2026-09-29T11:48:33.302Z
9fab75a7-a33b-412e-9dda-f934a392b545	2026-09-29T11:48:33.314Z
2f27b21a-74ea-4b1c-b826-824b5ef88fb6	2026-09-29T11:48:33.322Z
ed0a4b85-9e53-4fe7-a547-f1c8c245df48	2026-09-29T11:48:33.332Z
39af72eb-5f25-4b45-8504-2e4d6c39bccd	2026-09-29T11:48:33.349Z
e730e934-1006-4550-a443-c12680cb0719	2026-09-29T11:48:33.365Z
205c22e9-ce26-4b35-8f23-ea29fa42d9f5	2026-09-29T11:48:33.384Z
d26f24e9-e3ad-4228-a191-c250c7423afd	2026-09-29T11:48:33.394Z
d65ed8ce-595f-4e68-b9dc-9c54f036a177	2026-09-29T11:48:16.237Z
689390e4-7017-4751-b384-b34c8ef41116	2026-09-29T11:48:16.247Z
9c97c610-d3f5-428b-b495-99d5d3a4d84c	2026-09-29T11:48:16.499Z
e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	2026-09-29T11:48:16.499Z
42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	2026-09-29T11:48:16.518Z
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, api_key, created_at, updated_at, key_id) FROM stdin;
42ee4466-c20c-44ec-b8d2-4c4b82d60fe4	admin@fixture.example	admin	\N	$s$GqN+W6jmTJzDdwAo1g+X1zJJ9cPq32a7x8o1QYgPhfY=	2.aXYtdXNlci1rZXktYWRtaW4=|Y3QtdXNlci1rZXktYWRtaW4=|bWFjLXVzZXIta2V5LWFkbWlu	2.aXYtcHJpdmF0ZS1rZXktYWRtaW4=|Y3QtcHJpdmF0ZS1rZXktYWRtaW4=|bWFjLXByaXZhdGUta2V5LWFkbWlu	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA79KaNl7UgUkc9cIY/RqZqqGgV3H5lXkdGt8UiKrFGu9z9Vrpijmv4wp5zu4uaFjN/HnaKX4A3e9NWERvrM/lvBo0830zdxl0BduMj5I9bpdqwLF4yWBKZdh1aG9nE8jURefreLzQJT6vTqeI5zTd5cbmK2/bTgD/N+MoiOtycKchiVahAnCiHEkJ8iVWivCzUb0X04kbUWdnbmDFBcmWVxaqdI1WnW8wKdaKkoUy9gnIwAK4SpI+IFYabMjsf6Yo7x5bLef+L1Z0GTCEuPy1SXC7lQ/fPHmOYp3DftdTJbS8wJXM+YyYi1BBjaMbX9Hug1rDn0ffkhQ5MDmA/l8hsQIDAQAB	0	600000	\N	\N	6be22168-c4eb-4347-96f0-43b51cc9baf6	admin	active	0	\N	\N	\N	\N	\N	\N	\N	0	mZNfdNVVBiqxYbjqyIoFnv8OPIWBVc	2026-09-29T11:48:13.737Z	2026-09-29T11:48:13.737Z	\N
19290199-ab15-4919-823c-38b084e4e827	argon@fixture.example	argon	\N	$s$W+lyVVBuo3XFjFeJ03nmBLYW5e/7CfWye72M5HlLSe4=	2.aXYtdXNlci1rZXktYXJnb24=|Y3QtdXNlci1rZXktYXJnb24=|bWFjLXVzZXIta2V5LWFyZ29u	2.aXYtcHJpdmF0ZS1rZXktYXJnb24=|Y3QtcHJpdmF0ZS1rZXktYXJnb24=|bWFjLXByaXZhdGUta2V5LWFyZ29u	cHVibGljLWtleS1hcmdvbkBmaXh0dXJlLmV4YW1wbGU=	1	3	64	4	f315821b-41c1-4c77-9aa7-55ac35a7f76c	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	kxXpy4in6gU1a2wIEz3BsYNBx9eQPH	2026-09-29T11:48:13.822Z	2026-09-29T11:48:13.822Z	\N
032772a9-e7c1-4305-a14e-2ed1b3fef953	passkey@fixture.example	passkey	\N	$s$XliJimlT7SebP7w1GGf/mS5BjS1oVbTCS6xWDLyv6pU=	2.aXYtdXNlci1rZXktcGFzc2tleQ==|Y3QtdXNlci1rZXktcGFzc2tleQ==|bWFjLXVzZXIta2V5LXBhc3NrZXk=	2.aXYtcHJpdmF0ZS1rZXktcGFzc2tleQ==|Y3QtcHJpdmF0ZS1rZXktcGFzc2tleQ==|bWFjLXByaXZhdGUta2V5LXBhc3NrZXk=	cHVibGljLWtleS1wYXNza2V5QGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	fd107a09-2b65-40f4-b127-f46dbf452b38	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	la5QJcXhvOkz5Fbb6uM7O7CdBNv0sz	2026-09-29T11:48:13.973Z	2026-09-29T11:48:13.973Z	\N
9c97c610-d3f5-428b-b495-99d5d3a4d84c	manager@fixture.example	manager	\N	$s$REXx8y0VxdHhzpjjMmDi41ZDt9tGNK5k0p6FcQuiWkg=	2.aXYtdXNlci1rZXktbWFuYWdlcg==|Y3QtdXNlci1rZXktbWFuYWdlcg==|bWFjLXVzZXIta2V5LW1hbmFnZXI=	2.aXYtcHJpdmF0ZS1rZXktbWFuYWdlcg==|Y3QtcHJpdmF0ZS1rZXktbWFuYWdlcg==|bWFjLXByaXZhdGUta2V5LW1hbmFnZXI=	cHVibGljLWtleS1tYW5hZ2VyQGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	a15401fc-0c6a-4dfa-abd4-7b259140a9b5	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	TFpImBEUUvOFFhC9jpCjUynC5xRyp5	2026-09-29T11:48:13.994Z	2026-09-29T11:48:13.994Z	\N
e8b33f72-5185-4c6e-8c46-36d84d0fa7cf	custom@fixture.example	custom	\N	$s$GD7fPlOBFDpyFrBVype+ld73+GFN3qL3f5PnbEvDvjw=	2.aXYtdXNlci1rZXktY3VzdG9t|Y3QtdXNlci1rZXktY3VzdG9t|bWFjLXVzZXIta2V5LWN1c3RvbQ==	2.aXYtcHJpdmF0ZS1rZXktY3VzdG9t|Y3QtcHJpdmF0ZS1rZXktY3VzdG9t|bWFjLXByaXZhdGUta2V5LWN1c3RvbQ==	cHVibGljLWtleS1jdXN0b21AZml4dHVyZS5leGFtcGxl	0	600000	\N	\N	1d82103d-3e06-4da8-b9f5-a19ded3aa880	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	riCI56lwRMWcu93Z0NX7iJwoJPWmYw	2026-09-29T11:48:14.020Z	2026-09-29T11:48:14.020Z	\N
2f27b21a-74ea-4b1c-b826-824b5ef88fb6	legacy-domains@fixture.example	legacyDomains	\N	$s$ThzD3f5c2o23bK8eQsDPChYbUcJhCueCn9jO+g6Mi9E=	2.aXYtdXNlci1rZXktbGVnYWN5RG9tYWlucw==|Y3QtdXNlci1rZXktbGVnYWN5RG9tYWlucw==|bWFjLXVzZXIta2V5LWxlZ2FjeURvbWFpbnM=	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5RG9tYWlucw==|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5RG9tYWlucw==|bWFjLXByaXZhdGUta2V5LWxlZ2FjeURvbWFpbnM=	cHVibGljLWtleS1sZWdhY3ktZG9tYWluc0BmaXh0dXJlLmV4YW1wbGU=	0	600000	\N	\N	79076968-a13d-4ba3-9cc5-25715f91a9f6	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	GChwxGv7NYUuHzG123axNE5HqGmmmQ	2026-09-29T11:48:14.150Z	2026-09-29T11:48:14.150Z	\N
f175fcfb-4094-43d5-9e98-b98725c0283a	totp@fixture.example	totp	\N	$s$hBbC4Op8/KHS133xWtzuD1sZImuBtYgB8To+QXfDAxw=	2.aXYtdXNlci1rZXktdG90cA==|Y3QtdXNlci1rZXktdG90cA==|bWFjLXVzZXIta2V5LXRvdHA=	2.aXYtcHJpdmF0ZS1rZXktdG90cA==|Y3QtcHJpdmF0ZS1rZXktdG90cA==|bWFjLXByaXZhdGUta2V5LXRvdHA=	cHVibGljLWtleS10b3RwQGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	02209a72-96d1-476f-81cc-d62c9466a294	user	active	0	JBSWY3DPEHPK3PXPMOLIWARDENFIXTR	2YTD L3XA ZE6B KXEO MXGO TXV5 NPFV BI3K	\N	\N	\N	\N	\N	0	tEdngMAwYGv910XfHbclizFqT6kUOc	2026-09-29T11:48:13.874Z	2026-09-29T11:48:16.597Z	\N
d65ed8ce-595f-4e68-b9dc-9c54f036a177	yubikey@fixture.example	yubikey	\N	$s$lLKzUUFKIlj4T+kqGrt1n4W3QtHnevj46GJEvF0e8DE=	2.aXYtdXNlci1rZXkteXViaWtleQ==|Y3QtdXNlci1rZXkteXViaWtleQ==|bWFjLXVzZXIta2V5LXl1YmlrZXk=	2.aXYtcHJpdmF0ZS1rZXkteXViaWtleQ==|Y3QtcHJpdmF0ZS1rZXkteXViaWtleQ==|bWFjLXByaXZhdGUta2V5LXl1YmlrZXk=	cHVibGljLWtleS15dWJpa2V5QGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	8cfeb911-ecf4-4397-8654-d9ce6bdc8722	user	active	0	\N	BMFJ RWQ3 LC5A L5ZO D6N6 GGZA 4MAM FGJ5	cccccbhjklnr	\N	\N	\N	\N	1	IYY9iUhwimi1X2Y6ZrfuVjCAXdosKH	2026-09-29T11:48:13.927Z	2026-09-29T11:48:16.640Z	\N
689390e4-7017-4751-b384-b34c8ef41116	webauthn2fa@fixture.example	webauthn2fa	\N	$s$uz7XwhJidnBZZSvS9boBm8FAo8nWx8IArryz/TqDJ7I=	2.aXYtdXNlci1rZXktd2ViYXV0aG4yZmE=|Y3QtdXNlci1rZXktd2ViYXV0aG4yZmE=|bWFjLXVzZXIta2V5LXdlYmF1dGhuMmZh	2.aXYtcHJpdmF0ZS1rZXktd2ViYXV0aG4yZmE=|Y3QtcHJpdmF0ZS1rZXktd2ViYXV0aG4yZmE=|bWFjLXByaXZhdGUta2V5LXdlYmF1dGhuMmZh	cHVibGljLWtleS13ZWJhdXRobjJmYUBmaXh0dXJlLmV4YW1wbGU=	0	600000	\N	\N	12cf3157-93f1-42d3-a42c-4e13002c1d6e	user	active	0	\N	3XYA 4WLL LJ2L CU25 ZSDS XOKR CG6X T6VW	\N	\N	\N	\N	\N	0	0ntJQAyYSdElvpO1UpuSsWA44OGXI4	2026-09-29T11:48:13.950Z	2026-09-29T11:48:16.676Z	\N
8ac1796d-04aa-41bd-a31b-cb96118b4703	banned@fixture.example	banned	\N	$s$qL/peSpMi3O3MgGw8CLM9VYxZ8mrOjbVmV53MOMzSP4=	2.aXYtdXNlci1rZXktYmFubmVk|Y3QtdXNlci1rZXktYmFubmVk|bWFjLXVzZXIta2V5LWJhbm5lZA==	2.aXYtcHJpdmF0ZS1rZXktYmFubmVk|Y3QtcHJpdmF0ZS1rZXktYmFubmVk|bWFjLXByaXZhdGUta2V5LWJhbm5lZA==	cHVibGljLWtleS1iYW5uZWRAZml4dHVyZS5leGFtcGxl	0	600000	\N	\N	7274d938-2421-4286-982f-8ada06a77c76	user	banned	0	\N	\N	\N	\N	\N	\N	\N	0	hTPtNgdAF3OFObvGICNiWHsyV7brbQ	2026-09-29T11:48:14.055Z	2026-09-29T11:48:16.785Z	\N
502e2390-384d-40f3-83b7-53bfc6ee882c	legacy-rawhash@fixture.example	legacyRawHash	\N	aGFzaC1sZWdhY3ktcmF3aGFzaEBmaXh0dXJlLmV4YW1wbGU=	2.aXYtdXNlci1rZXktbGVnYWN5UmF3SGFzaA==|Y3QtdXNlci1rZXktbGVnYWN5UmF3SGFzaA==|bWFjLXVzZXIta2V5LWxlZ2FjeVJhd0hhc2g=	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5UmF3SGFzaA==|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5UmF3SGFzaA==|bWFjLXByaXZhdGUta2V5LWxlZ2FjeVJhd0hhc2g=	cHVibGljLWtleS1sZWdhY3ktcmF3aGFzaEBmaXh0dXJlLmV4YW1wbGU=	0	600000	\N	\N	c7c02ddc-21b7-43cc-a551-09f7e5d6f39e	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	KIQ5f8hFZRGFpiIS8Yem7LW88YCnSW	2026-09-29T11:48:14.081Z	2026-09-29T11:48:14.081Z	\N
9fab75a7-a33b-412e-9dda-f934a392b545	legacy-apikey@fixture.example	legacyApiKey	\N	$s$0Yoo3LDl+PcwSvN/4rPTD8/SEFOpaj3pEPuBQcQPpY8=	2.aXYtdXNlci1rZXktbGVnYWN5QXBpS2V5|Y3QtdXNlci1rZXktbGVnYWN5QXBpS2V5|bWFjLXVzZXIta2V5LWxlZ2FjeUFwaUtleQ==	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5QXBpS2V5|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5QXBpS2V5|bWFjLXByaXZhdGUta2V5LWxlZ2FjeUFwaUtleQ==	cHVibGljLWtleS1sZWdhY3ktYXBpa2V5QGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	b0858aed-7227-4b60-92db-9132e79bf65d	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	sha256:e2de8b66ed18100f4fa2d011aea2776d6580f892a19ed0511a42934ff871a857	2026-09-29T11:48:14.112Z	2026-09-29T11:48:14.112Z	\N
d26f24e9-e3ad-4228-a191-c250c7423afd	legacy-session@fixture.example	legacySession	\N	$s$lyJuKKPsKZtC1jL1jrDzIV8daqgIo2xr3+7ABlrR1O0=	2.aXYtdXNlci1rZXktbGVnYWN5U2Vzc2lvbg==|Y3QtdXNlci1rZXktbGVnYWN5U2Vzc2lvbg==|bWFjLXVzZXIta2V5LWxlZ2FjeVNlc3Npb24=	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5U2Vzc2lvbg==|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5U2Vzc2lvbg==|bWFjLXByaXZhdGUta2V5LWxlZ2FjeVNlc3Npb24=	cHVibGljLWtleS1sZWdhY3ktc2Vzc2lvbkBmaXh0dXJlLmV4YW1wbGU=	0	600000	\N	\N	e0d44b3a-1d29-49c7-9e2d-1a0a3481ee33	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	n9i7fjOAXIvqwnsf91IkL6i6dHgzdQ	2026-09-29T11:48:14.267Z	2026-09-29T11:48:14.267Z	\N
1e7bbf40-54d5-49f3-812e-6336f876a0cd	legacy-cipher@fixture.example	legacyCipher	\N	$s$rFC9CaFV5OUbayfo+fe/VgfGnOM5blcau8sFFKCmMeI=	2.aXYtdXNlci1rZXktbGVnYWN5Q2lwaGVy|Y3QtdXNlci1rZXktbGVnYWN5Q2lwaGVy|bWFjLXVzZXIta2V5LWxlZ2FjeUNpcGhlcg==	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5Q2lwaGVy|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5Q2lwaGVy|bWFjLXByaXZhdGUta2V5LWxlZ2FjeUNpcGhlcg==	cHVibGljLWtleS1sZWdhY3ktY2lwaGVyQGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	ad5fb3e5-0fdd-4fc7-889c-404e9d74ca4f	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	LO8nrJLU6KDnzxrmprFxYeq2jpAbyw	2026-09-29T11:48:14.292Z	2026-09-29T11:48:14.292Z	\N
b47224e1-7541-4fed-8262-51a236e3f206	vault@fixture.example	vault	the usual one	$s$7Z2z3EZLLAuSJaW2oW/gj6pS1nwdT98/mNLoI/xYVGs=	2.aXYtdXNlci1rZXktdmF1bHQ=|Y3QtdXNlci1rZXktdmF1bHQ=|bWFjLXVzZXIta2V5LXZhdWx0	2.aXYtcHJpdmF0ZS1rZXktdmF1bHQ=|Y3QtcHJpdmF0ZS1rZXktdmF1bHQ=|bWFjLXByaXZhdGUta2V5LXZhdWx0	cHVibGljLWtleS12YXVsdEBmaXh0dXJlLmV4YW1wbGU=	0	350000	\N	\N	94821132-03dd-446c-9dfe-fa442cd600b7	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	aaG5rU7J3Sk87q2NPFVBqv7MHgdqG2	2026-09-29T11:48:13.796Z	2026-09-29T11:48:16.104Z	\N
ed0a4b85-9e53-4fe7-a547-f1c8c245df48	legacy-totp@fixture.example	legacyTotp	\N	$s$PZ0bKUUGvzwPfXOD+OvBNjW1vegsblgQ9/uI5fxkKX4=	2.aXYtdXNlci1rZXktbGVnYWN5VG90cA==|Y3QtdXNlci1rZXktbGVnYWN5VG90cA==|bWFjLXVzZXIta2V5LWxlZ2FjeVRvdHA=	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5VG90cA==|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5VG90cA==|bWFjLXByaXZhdGUta2V5LWxlZ2FjeVRvdHA=	cHVibGljLWtleS1sZWdhY3ktdG90cEBmaXh0dXJlLmV4YW1wbGU=	0	600000	\N	\N	f04e012e-41db-465b-9854-436e7243b386	user	active	0	jbsw y3dp-ehpk 3pxp-moli ward-enle gacy==	abcdefghijklmnopqrstuvwxyz234567	\N	\N	\N	\N	\N	0	XW4qsgsR8T1tAL8fAqnzZy8rlBbgp5	2026-09-29T11:48:14.179Z	2026-09-29T11:48:14.179Z	\N
39af72eb-5f25-4b45-8504-2e4d6c39bccd	legacy-yubikey@fixture.example	legacyYubikey	\N	$s$Z4WlSMfXvCDRlh9T/Iqfdc+ISVGHbhKrlgY7sGzZfhI=	2.aXYtdXNlci1rZXktbGVnYWN5WXViaWtleQ==|Y3QtdXNlci1rZXktbGVnYWN5WXViaWtleQ==|bWFjLXVzZXIta2V5LWxlZ2FjeVl1YmlrZXk=	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5WXViaWtleQ==|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5WXViaWtleQ==|bWFjLXByaXZhdGUta2V5LWxlZ2FjeVl1YmlrZXk=	cHVibGljLWtleS1sZWdhY3kteXViaWtleUBmaXh0dXJlLmV4YW1wbGU=	0	600000	\N	\N	a00eb6cc-2b4d-4617-9965-4d22bbf95ce1	user	active	0	\N	\N	  CCCCCBHJKLNV 	\N	\N	\N	\N	0	9SR3A2yLndUWRoeogIn8c34uJQmaoD	2026-09-29T11:48:14.201Z	2026-09-29T11:48:14.201Z	\N
e730e934-1006-4550-a443-c12680cb0719	legacy-kdf@fixture.example	legacyKdf	\N	$s$5ZZDWnC4J5kKO40GxZ4jCkonrOAqBggd0MDsehaogXA=	2.aXYtdXNlci1rZXktbGVnYWN5S2Rm|Y3QtdXNlci1rZXktbGVnYWN5S2Rm|bWFjLXVzZXIta2V5LWxlZ2FjeUtkZg==	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5S2Rm|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5S2Rm|bWFjLXByaXZhdGUta2V5LWxlZ2FjeUtkZg==	cHVibGljLWtleS1sZWdhY3kta2RmQGZpeHR1cmUuZXhhbXBsZQ==	0	5000	\N	\N	8f02eec0-7cd0-4b11-9212-592c3b40860d	user	active	0	\N	\N	\N	\N	\N	\N	\N	0	pJGsD44ge6Ma0AMfS1bhFNbb0dsmjM	2026-09-29T11:48:14.222Z	2026-09-29T11:48:14.222Z	\N
205c22e9-ce26-4b35-8f23-ea29fa42d9f5	legacy-status@fixture.example	legacyStatus	\N	$s$PONk/9V4Fj02Fdgp6WWIHHdIOBBomiSm8yfWNWY6zZE=	2.aXYtdXNlci1rZXktbGVnYWN5U3RhdHVz|Y3QtdXNlci1rZXktbGVnYWN5U3RhdHVz|bWFjLXVzZXIta2V5LWxlZ2FjeVN0YXR1cw==	2.aXYtcHJpdmF0ZS1rZXktbGVnYWN5U3RhdHVz|Y3QtcHJpdmF0ZS1rZXktbGVnYWN5U3RhdHVz|bWFjLXByaXZhdGUta2V5LWxlZ2FjeVN0YXR1cw==	cHVibGljLWtleS1sZWdhY3ktc3RhdHVzQGZpeHR1cmUuZXhhbXBsZQ==	0	600000	\N	\N	1e961452-c0b6-47b0-83c8-69b52493410b	member	disabled	0	\N	\N	\N	\N	\N	\N	\N	0	R0LV4UMuBAU1RpQvcAcrXuZIzT6pqY	2026-09-29T11:48:14.244Z	2026-09-29T11:48:14.244Z	\N
\.


--
-- Data for Name: webauthn_challenges; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.webauthn_challenges (challenge_hash, scope, user_id, expires_at, used_at, created_at) FROM stdin;
jGKhRQkOUvQS5OdteuzWWADtgNe7yGPhiPqJG2fMnPM	Authentication	\N	1790683516745	1790682496747	1790682496745
\.


--
-- Data for Name: webauthn_credentials; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.webauthn_credentials (id, user_id, purpose, name, public_key, credential_id, counter, type, aa_guid, transports, encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at) FROM stdin;
16b82afe-8790-4674-a0e0-3cedcd497ecd	689390e4-7017-4751-b384-b34c8ef41116	twoFactor	Fixture security key	pQECAyYgASFYIAzxd4L7Y1O9h7Sho5xLUwFXrtK6i5ob4fO8J6lD8bmpIlgg6opwHVk4-SQdvmL2wCvCwiOZogcuGq4J5LexhSJH7gk	MM3JP9259bm26-ARe9AqRscvDp0GVgH2p4WTYL1vM_s	1	public-key	00000000-0000-0000-0000-000000000000	["internal","hybrid"]	\N	\N	\N	0	2026-09-29T11:48:16.676Z	2026-09-29T11:48:16.700Z
e80f2687-447b-40c8-a7c1-83a1de1ba6d8	032772a9-e7c1-4305-a14e-2ed1b3fef953	login	Phone passkey	pQECAyYgASFYIHgEOGF6H05Kg3Wq_eX5uQf3SFlD0reb6mt9PXP7Un2jIlggJ_nNr9GWD954AiLxKD9WU9lv09wjeVVwN8XKoWMJVKU	1uwWIStYi_26wKKjL4dOtzEJinNJE8uZJNUyIolA_iA	0	public-key	00000000-0000-0000-0000-000000000000	\N	\N	\N	\N	1	2026-09-29T11:48:16.729Z	2026-09-29T11:48:16.729Z
ef284549-a046-4e28-87a5-2fcd84ae4349	032772a9-e7c1-4305-a14e-2ed1b3fef953	login	Account passkey	pQECAyYgASFYIMtblvPX2xVeD88Da8UDuy6jXj36napHMKd6Jrr4_pt4IlggL62Pr6-K5ysHwp3DNaZPMQy2GjEHqihg9FGOo-WLu1Y	jSJnZ7LAeoST5nTgNI2jqwTrUGEV0gt7dPiKrgKu2x0	0	public-key	00000000-0000-0000-0000-000000000000	["internal","hybrid"]	\N	\N	\N	0	2026-09-29T11:48:16.744Z	2026-09-29T11:48:16.744Z
af717776-95e4-4e1b-a350-26cf8bcd4b6d	032772a9-e7c1-4305-a14e-2ed1b3fef953	login	Laptop passkey	pQECAyYgASFYIAk0a7ALtIm5sTw55NoyxfgpMUlw7u2HadrwBVVX5vE0Ilgg9M6axbDGwXyAFSLJpULl9YMfKBp52YnuqZm2ZHriSZk	695uXT3Cg5_pRdLiNvjliwIZjB2XXzW7KxVZ-TkPHlc	1	public-key	00000000-0000-0000-0000-000000000000	["internal","hybrid"]	4.cnNhLXByZi11c2VyLWtleQ==	2.aXYtcHJmLXB1YmxpYy1rZXk=|Y3QtcHJmLXB1YmxpYy1rZXk=|bWFjLXByZi1wdWJsaWMta2V5	2.aXYtcHJmLXByaXZhdGUta2V5|Y3QtcHJmLXByaXZhdGUta2V5|bWFjLXByZi1wcml2YXRlLWtleQ==	1	2026-09-29T11:48:16.715Z	2026-09-29T11:48:16.748Z
\.


--
-- Name: attachments attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: auth_requests auth_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_requests
    ADD CONSTRAINT auth_requests_pkey PRIMARY KEY (id);


--
-- Name: cipher_collections cipher_collections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cipher_collections
    ADD CONSTRAINT cipher_collections_pkey PRIMARY KEY (cipher_id, collection_id);


--
-- Name: cipher_user_state cipher_user_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cipher_user_state
    ADD CONSTRAINT cipher_user_state_pkey PRIMARY KEY (cipher_id, user_id);


--
-- Name: ciphers ciphers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciphers
    ADD CONSTRAINT ciphers_pkey PRIMARY KEY (id);


--
-- Name: collection_members collection_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_members
    ADD CONSTRAINT collection_members_pkey PRIMARY KEY (collection_id, membership_id);


--
-- Name: collections collections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collections
    ADD CONSTRAINT collections_pkey PRIMARY KEY (id);


--
-- Name: config config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.config
    ADD CONSTRAINT config_pkey PRIMARY KEY (key);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (user_id, device_identifier);


--
-- Name: domain_settings domain_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_settings
    ADD CONSTRAINT domain_settings_pkey PRIMARY KEY (user_id);


--
-- Name: folders folders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_pkey PRIMARY KEY (id);


--
-- Name: invites invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invites
    ADD CONSTRAINT invites_pkey PRIMARY KEY (code);


--
-- Name: login_attempts_ip login_attempts_ip_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_attempts_ip
    ADD CONSTRAINT login_attempts_ip_pkey PRIMARY KEY (ip);


--
-- Name: org_memberships org_memberships_org_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_org_id_user_id_key UNIQUE (org_id, user_id);


--
-- Name: org_memberships org_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: rate_limit_buckets rate_limit_buckets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit_buckets
    ADD CONSTRAINT rate_limit_buckets_pkey PRIMARY KEY (bucket_key);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (token);


--
-- Name: sends sends_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sends
    ADD CONSTRAINT sends_pkey PRIMARY KEY (id);


--
-- Name: totp_login_replays totp_login_replays_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_login_replays
    ADD CONSTRAINT totp_login_replays_pkey PRIMARY KEY (user_id, time_counter);


--
-- Name: trusted_two_factor_device_tokens trusted_two_factor_device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trusted_two_factor_device_tokens
    ADD CONSTRAINT trusted_two_factor_device_tokens_pkey PRIMARY KEY (token);


--
-- Name: used_attachment_download_tokens used_attachment_download_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.used_attachment_download_tokens
    ADD CONSTRAINT used_attachment_download_tokens_pkey PRIMARY KEY (jti);


--
-- Name: user_revisions user_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_revisions
    ADD CONSTRAINT user_revisions_pkey PRIMARY KEY (user_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: webauthn_challenges webauthn_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_challenges
    ADD CONSTRAINT webauthn_challenges_pkey PRIMARY KEY (challenge_hash);


--
-- Name: webauthn_credentials webauthn_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);


--
-- Name: idx_attachments_cipher; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attachments_cipher ON public.attachments USING btree (cipher_id);


--
-- Name: idx_audit_logs_actor_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_actor_created ON public.audit_logs USING btree (actor_user_id, created_at);


--
-- Name: idx_audit_logs_category_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_category_created ON public.audit_logs USING btree (category, created_at);


--
-- Name: idx_audit_logs_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_created_at ON public.audit_logs USING btree (created_at);


--
-- Name: idx_audit_logs_level_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_level_created ON public.audit_logs USING btree (level, created_at);


--
-- Name: idx_auth_requests_device_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_requests_device_pending ON public.auth_requests USING btree (user_id, request_device_identifier, creation_date);


--
-- Name: idx_auth_requests_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_requests_user_created ON public.auth_requests USING btree (user_id, creation_date);


--
-- Name: idx_auth_requests_user_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_requests_user_pending ON public.auth_requests USING btree (user_id, approved, response_date, authentication_date, creation_date);


--
-- Name: idx_cipher_collections_collection; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cipher_collections_collection ON public.cipher_collections USING btree (collection_id);


--
-- Name: idx_cipher_user_state_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cipher_user_state_user ON public.cipher_user_state USING btree (user_id);


--
-- Name: idx_ciphers_org_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciphers_org_updated ON public.ciphers USING btree (organization_id, updated_at);


--
-- Name: idx_ciphers_user_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciphers_user_archived ON public.ciphers USING btree (user_id, archived_at);


--
-- Name: idx_ciphers_user_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciphers_user_deleted ON public.ciphers USING btree (user_id, deleted_at);


--
-- Name: idx_ciphers_user_deleted_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciphers_user_deleted_updated ON public.ciphers USING btree (user_id, deleted_at, updated_at);


--
-- Name: idx_ciphers_user_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciphers_user_folder ON public.ciphers USING btree (user_id, folder_id);


--
-- Name: idx_ciphers_user_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciphers_user_updated ON public.ciphers USING btree (user_id, updated_at);


--
-- Name: idx_collection_members_membership; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collection_members_membership ON public.collection_members USING btree (membership_id);


--
-- Name: idx_collections_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collections_org ON public.collections USING btree (org_id);


--
-- Name: idx_devices_user_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_devices_user_last_seen ON public.devices USING btree (user_id, last_seen_at);


--
-- Name: idx_devices_user_push; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_devices_user_push ON public.devices USING btree (user_id, push_token);


--
-- Name: idx_devices_user_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_devices_user_updated ON public.devices USING btree (user_id, updated_at);


--
-- Name: idx_folders_user_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_folders_user_updated ON public.folders USING btree (user_id, updated_at);


--
-- Name: idx_invites_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_invites_created_by ON public.invites USING btree (created_by, created_at);


--
-- Name: idx_invites_status_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_invites_status_expires ON public.invites USING btree (status, expires_at);


--
-- Name: idx_org_memberships_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_memberships_user ON public.org_memberships USING btree (user_id);


--
-- Name: idx_rate_limit_buckets_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rate_limit_buckets_expires ON public.rate_limit_buckets USING btree (expires_at);


--
-- Name: idx_refresh_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_expires ON public.refresh_tokens USING btree (expires_at);


--
-- Name: idx_refresh_tokens_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_user ON public.refresh_tokens USING btree (user_id);


--
-- Name: idx_sends_user_deletion; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sends_user_deletion ON public.sends USING btree (user_id, deletion_date);


--
-- Name: idx_sends_user_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sends_user_updated ON public.sends USING btree (user_id, updated_at);


--
-- Name: idx_sends_user_updated_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sends_user_updated_id ON public.sends USING btree (user_id, updated_at, id);


--
-- Name: idx_totp_login_replays_consumed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_login_replays_consumed_at ON public.totp_login_replays USING btree (consumed_at);


--
-- Name: idx_trusted_two_factor_device_tokens_user_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trusted_two_factor_device_tokens_user_device ON public.trusted_two_factor_device_tokens USING btree (user_id, device_identifier);


--
-- Name: idx_webauthn_challenges_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_challenges_expires ON public.webauthn_challenges USING btree (expires_at);


--
-- Name: idx_webauthn_challenges_user_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_challenges_user_scope ON public.webauthn_challenges USING btree (user_id, scope);


--
-- Name: idx_webauthn_credentials_credential_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_webauthn_credentials_credential_id ON public.webauthn_credentials USING btree (credential_id);


--
-- Name: idx_webauthn_credentials_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_credentials_user ON public.webauthn_credentials USING btree (user_id);


--
-- Name: idx_webauthn_credentials_user_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_credentials_user_updated ON public.webauthn_credentials USING btree (user_id, updated_at);


--
-- Name: attachments attachments_cipher_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_cipher_id_fkey FOREIGN KEY (cipher_id) REFERENCES public.ciphers(id) ON DELETE CASCADE;


--
-- Name: audit_logs audit_logs_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: auth_requests auth_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_requests
    ADD CONSTRAINT auth_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: cipher_collections cipher_collections_cipher_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cipher_collections
    ADD CONSTRAINT cipher_collections_cipher_id_fkey FOREIGN KEY (cipher_id) REFERENCES public.ciphers(id) ON DELETE CASCADE;


--
-- Name: cipher_collections cipher_collections_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cipher_collections
    ADD CONSTRAINT cipher_collections_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: cipher_user_state cipher_user_state_cipher_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cipher_user_state
    ADD CONSTRAINT cipher_user_state_cipher_id_fkey FOREIGN KEY (cipher_id) REFERENCES public.ciphers(id) ON DELETE CASCADE;


--
-- Name: cipher_user_state cipher_user_state_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cipher_user_state
    ADD CONSTRAINT cipher_user_state_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: ciphers ciphers_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciphers
    ADD CONSTRAINT ciphers_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: ciphers ciphers_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciphers
    ADD CONSTRAINT ciphers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: collection_members collection_members_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_members
    ADD CONSTRAINT collection_members_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: collection_members collection_members_membership_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_members
    ADD CONSTRAINT collection_members_membership_id_fkey FOREIGN KEY (membership_id) REFERENCES public.org_memberships(id) ON DELETE CASCADE;


--
-- Name: collections collections_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collections
    ADD CONSTRAINT collections_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: devices devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: domain_settings domain_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_settings
    ADD CONSTRAINT domain_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: folders folders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: invites invites_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invites
    ADD CONSTRAINT invites_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: invites invites_used_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invites
    ADD CONSTRAINT invites_used_by_fkey FOREIGN KEY (used_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: org_memberships org_memberships_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: org_memberships org_memberships_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: sends sends_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sends
    ADD CONSTRAINT sends_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: totp_login_replays totp_login_replays_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_login_replays
    ADD CONSTRAINT totp_login_replays_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: trusted_two_factor_device_tokens trusted_two_factor_device_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trusted_two_factor_device_tokens
    ADD CONSTRAINT trusted_two_factor_device_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_revisions user_revisions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_revisions
    ADD CONSTRAINT user_revisions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: webauthn_credentials webauthn_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


