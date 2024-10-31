auth_hub
=====

Build
-----
    $ make rel
    $ ./_build/prod/rel/auth_hub/bin/auth_hub console
    
or

    $ ./run_main.sh
    $ ./run_cluster1.sh

Common tests + EUnit tests
----
    $ rebar3 ct --spec apps/auth_hub/tests/test.spec

WRK
----
    $ wrk -t2 -c3 -d1m -R5700 -s apps/auth_hub/wrk/show_all_users.lua http://127.0.0.1:1913
    
Data developer
---- 
    Transmission base: http, POST.
    Transmission format: json.

    Roles: "read", "write", "exec".

    Cache saves in ets. Table 'auth_hub' in key 'server_cache'. 

    login: admin
    pass: 12345678

API
-----
    auth_hub_server:
        State = #{<<"User">> => [<<"Role">>, ..], ..},
    
        handle_call:                                                                Have cache     Benchmark(wrk2)   Delay(wrk2)
            user_add({user_add, <<"NewUser">>}),                          (127 ms) | (106 ms)             (26 r/s) | (437 ms)
            user_delete({user_delete, <<"User">>}),                       (271 ms) | (297 ms)                      |
            show_all_users({show_all_users}),                             (114 ms) | (2 ms)            (15200 r/s) | (19 ms)
        
            roles_add({roles_add, <<"User">>, [<<"Role">>, ...]}),        (459 ms) | (246 ms)             (95 r/s) | (437 ms)
            roles_delete({roles_delete, <<"User">>, [<<"Role">>, ...]}),  (185 ms) | (208 ms)                      |
            show_roles({show_roles, <<"User">>}),                         (185 ms) | (2 ms)                        |
        
            show_allow_roles({show_allow_roles}).                         (1 ms)   | (1 ms)            (52000 r/s) | (17 ms)

        
JSON requests example
-----
    {"method":"show_allow_roles"}

    {"method":"show_all_users"}
    {"method":"user_delete", "user":"mike_test"}
    {"method":"user_add", "user":"mike_test"}
    
    {"method":"roles_add", "user":"karl_test", "roles":["read"]}
    {"method":"show_roles", "user":"karl_test"}
    {"method":"roles_delete", "user":"karl_test", "roles":["exec"]}


PgSql Create scripts
---
-- Table: public.allow_roles
-- DROP TABLE IF EXISTS public.allow_roles;
CREATE TABLE IF NOT EXISTS public.allow_roles
(
subsystem character varying COLLATE pg_catalog."default" NOT NULL,
role character varying COLLATE pg_catalog."default" NOT NULL,
description character varying COLLATE pg_catalog."default",
CONSTRAINT allow_roles_pkey PRIMARY KEY (subsystem, role),
CONSTRAINT c1 FOREIGN KEY (subsystem)
REFERENCES public.allow_subsystems (subsystem) MATCH SIMPLE
ON UPDATE NO ACTION
ON DELETE NO ACTION
NOT VALID
)
TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.allow_roles
OWNER to admin;



-- Table: public.allow_subsystems
-- DROP TABLE IF EXISTS public.allow_subsystems;
CREATE TABLE IF NOT EXISTS public.allow_subsystems
(
subsystem character varying COLLATE pg_catalog."default" NOT NULL,
description character varying COLLATE pg_catalog."default",
CONSTRAINT allow_subsystems_pkey PRIMARY KEY (subsystem)
)
TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.allow_subsystems
OWNER to admin;



-- Table: public.roles
-- DROP TABLE IF EXISTS public.roles;
CREATE TABLE IF NOT EXISTS public.roles
(
login character varying(50) COLLATE pg_catalog."default" NOT NULL,
subsystem character varying(10) COLLATE pg_catalog."default" NOT NULL,
role character varying(10) COLLATE pg_catalog."default" NOT NULL,
CONSTRAINT roles_pkey PRIMARY KEY (login, subsystem, role),
CONSTRAINT const_1 FOREIGN KEY (role, subsystem)
REFERENCES public.allow_roles (role, subsystem) MATCH SIMPLE
ON UPDATE NO ACTION
ON DELETE NO ACTION
NOT VALID,
CONSTRAINT const_2 FOREIGN KEY (login)
REFERENCES public.users (login) MATCH SIMPLE
ON UPDATE NO ACTION
ON DELETE NO ACTION
NOT VALID
)
TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.roles
OWNER to admin;



-- Table: public.sids
-- DROP TABLE IF EXISTS public.sids;
CREATE TABLE IF NOT EXISTS public.sids
(
login character varying COLLATE pg_catalog."default" NOT NULL,
subsystem character varying COLLATE pg_catalog."default" NOT NULL,
sid character varying COLLATE pg_catalog."default" NOT NULL,
ts_end timestamp without time zone NOT NULL,
CONSTRAINT sids_pkey PRIMARY KEY (login, subsystem),
CONSTRAINT "unique" UNIQUE (sid),
CONSTRAINT c2 FOREIGN KEY (subsystem)
REFERENCES public.allow_subsystems (subsystem) MATCH SIMPLE
ON UPDATE NO ACTION
ON DELETE NO ACTION
NOT VALID,
CONSTRAINT const1 FOREIGN KEY (login)
REFERENCES public.users (login) MATCH SIMPLE
ON UPDATE NO ACTION
ON DELETE NO ACTION
)
TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.sids
OWNER to admin;



-- Table: public.users
-- DROP TABLE IF EXISTS public.users;
CREATE TABLE IF NOT EXISTS public.users
(
login character varying(50) COLLATE pg_catalog."default" NOT NULL,
passhash character varying(100) COLLATE pg_catalog."default" NOT NULL,
CONSTRAINT users_pkey PRIMARY KEY (login)
)
TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.users
OWNER to admin;