auth_hub
=====

Build
-----
---
- Start service


    $ make rel
    $ ./_build/prod/rel/auth_hub/bin/auth_hub console

    or

    $ ./run_main.sh

- Start (Common tests + EUnit tests)


    $ rebar3 ct --spec apps/auth_hub/tests/test.spec

- Start WRK


    $ wrk -t2 -c3 -d1m -R5700 -s apps/auth_hub/wrk/show_all_users.lua http://127.0.0.1:1913
    
API
----
---
open session

    POST http://127.0.0.1:1913/session/open
    Content-Type: application/json
    {
        "login": "admin",
        "pass": "12345678"
    }  
    
    - response 200 -
    {
        "success": {
            "sid": "3c552a129a4711ef884b18c04d540e8a",
            "ts_end": "2024-11-04 03:23:41",
            "ts_start": "2024-11-04 02:53:41"
        }
    }
    
check sid

    GET http://127.0.0.1:1913/session/check?sid=6cf1751a9da611ef8a7918c04d540e8a
    Content-Type: application/json
    
    - response 200 -
    {
        "success": {
            "active_session": true
        }
    }

get login

    GET http://127.0.0.1:1913/identification/login
    Content-Type: application/json
    sid: fdfdb23a9d4211efb25d18c04d540e8a
    
    - response 200 -
    {
        "success": {
            "login": "admin"
        }
    }

get roles

    POST http://127.0.0.1:1913/authorization/roles
    Content-Type: application/json
    sid: fdfdb23a9d4211efb25d18c04d540e8a
    {
        "subsystem": "authHub"
    }

    - response 200 -
    {
    "success": {
        "roles": [
            "am",
            "cr"
        ],
        "subsystem": "authHub"
    }
    }

create users

    POST http://127.0.0.1:1913/api
    Content-Type: application/json
    sid: 7a9bdcfea34c11ef801c18c04d540e8a
    {
        "method": "create_users",
        "users": [
            {
                "login": "kv190901kma",
                "pass": "22222222"
            }
        ]
    }

    - response 200 -
    {
        "users": [
            {
                "login": "kv190901kma",
                "success": true
            }
        ]
    }

delete users

    POST http://127.0.0.1:1913/api
    Content-Type: application/json
    sid: 7a9bdcfea34c11ef801c18c04d540e8a
    {
        "method": "delete_users",
        "logins": ["MissL", "Mr_L"]
    }

    - response 200 -
    {
        "users": [
            {
                "login": "MissL",
                "success": true
            },
            {
                "login": "Mr_L",
                "success": true
            }
        ]
    }

get all users info

    GET http://127.0.0.1:1913/api/users/info
    Content-Type: application/json
    sid: 7a9bdcfea34c11ef801c18c04d540e8a
    
    - response 200 -
    {
        "success": {
            "info": [
                {
                    "has_active_sid": true,
                    "login": "admin",
                    "subsystem_roles": {
                        "authHub": ["cr", "am"]
                    }
                },
                {
                    "active_sid": false,
                    "login": "broker",
                    "subsystem_roles": {
                        "mainBroker": ["am"]
                    }
                }
            ]
        }
    }

get allow subsystems roles

    GET http://127.0.0.1:1913/api/allow/subsystems/roles/info
    Content-Type: application/json
    sid: 7a9bdcfea34c11ef801c18c04d540e8a

    - response 200 -
    {
    "success": {
        "info": [
            {
                "allow_roles": [
                    {
                        "description": "All admin roles",
                        "role": "am"
                    },
                    {
                        "description": "Delete user roles",
                        "role": "dr"
                    },
                    {
                        "description": "Add roles for user",
                        "role": "ar"
                    },
                    {
                        "description": "Delete users",
                        "role": "dl"
                    },
                    {
                        "description": "Create users",
                        "role": "cr"
                    }
                ],
                "description": "Service auth_hub",
                "subsystem": "authHub"
            },
            {
                "allow_roles": [
                    {
                        "description": "Administrator - all roles",
                        "role": "am"
                    }
                ],
                "description": "Service main_broker",
                "subsystem": "mainBroker"
            },
            {
                "allow_roles": [],
                "description": "Service where application save data",
                "subsystem": "bigBag"
            }
        ]
    }
    }

add roles 

    POST http://127.0.0.1:1913/api/roles/change
    Content-Type: application/json
    sid: 7a9bdcfea34c11ef801c18c04d540e8a
    {
    "method": "add_roles",
    "changes": [
        {
            "login": "kv190901kma",
            "subsystem": "authHub",
            "roles": ["cr", "dl"]
        },
        {
            "login": "dn190901kma",
            "subsystem": "authHub",
            "roles": ["cr", "dl"]
        }
    ]
    }

    - response 200 -
    {
    "results": [
        {
            "login": "kv190901kma",
            "roles": [
                "cr",
                "dl"
            ],
            "subsystem": "authHub",
            "success": true
        },
        {
            "login": "dn190901kma",
            "roles": [
                "cr",
                "dl"
            ],
            "subsystem": "authHub",
            "success": true
        }
    ]
    }

delete roles

    POST http://127.0.0.1:1913/api/roles/change
    Content-Type: application/json
    sid: 7a9bdcfea34c11ef801c18c04d540e8a
    {
    "method": "delete_roles",
    "changes": [
        {
            "login": "kv190901kma",
            "subsystem": "authHub",
            "roles": ["cr", "dl"]
        },
        {
            "login": "dn190901kma",
            "subsystem": "authHub",
            "roles": ["cr", "dl"]
        }
    ]
    }

    - response 200 -
    {
    "results": [
        {
            "login": "kv190901kma",
            "roles": [
                "cr",
                "dl"
            ],
            "subsystem": "authHub",
            "success": true
        },
        {
            "login": "dn190901kma",
            "roles": [
                "cr",
                "dl"
            ],
            "subsystem": "authHub",
            "success": true
        }
    ]
    }





PgSql Create scripts
----
---
Tables
---
allow_roles

    CREATE TABLE public.allow_roles (
        subsystem varchar NOT NULL,
        "role" varchar NOT NULL,
        description varchar NULL,
        CONSTRAINT allow_roles_pkey PRIMARY KEY (subsystem, role),
        CONSTRAINT c1 FOREIGN KEY (subsystem) REFERENCES public.allow_subsystems(subsystem)
    );

allow_subsystems

    CREATE TABLE public.allow_subsystems (
	    subsystem varchar NOT NULL,
	    description varchar NULL,
	    CONSTRAINT allow_subsystems_pkey PRIMARY KEY (subsystem)
    );

roles

    CREATE TABLE public.roles (
	    login varchar(50) NOT NULL,
	    subsystem varchar(10) NOT NULL,
	    "role" varchar(10) NOT NULL,
	    CONSTRAINT roles_pkey PRIMARY KEY (login, subsystem, role),
	    CONSTRAINT const_1 FOREIGN KEY ("role",subsystem) REFERENCES <?>(),
	    CONSTRAINT const_2 FOREIGN KEY (login) REFERENCES public.users(login)
    );

sids

    CREATE TABLE public.sids (
	    login varchar NOT NULL,
	    sid varchar NOT NULL,
	    ts_end timestamp NOT NULL,
	    CONSTRAINT sids_pkey PRIMARY KEY (login),
	    CONSTRAINT "unique" UNIQUE (sid),
	    CONSTRAINT const1 FOREIGN KEY (login) REFERENCES public.users(login)
    );

users

    CREATE TABLE public.users (
	    login varchar(50) NOT NULL,
	    passhash varchar(100) NOT NULL,
	    CONSTRAINT login_pk PRIMARY KEY (login),
	    CONSTRAINT unique_pass UNIQUE (passhash)
    );


Functions
---

delete_user(varchar)

    CREATE OR REPLACE FUNCTION public.delete_user(login_i character varying)
        RETURNS character varying
        LANGUAGE plpgsql
    AS $function$#variable_conflict use_column
    BEGIN

	    DELETE FROM roles WHERE login=login_i;
	    DELETE FROM sids WHERE login=login_i;
	    DELETE FROM users WHERE login=login_i;
	    RETURN 'ok';

    END;$function$
    ;