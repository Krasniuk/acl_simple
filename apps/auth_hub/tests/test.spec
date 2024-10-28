{suites, "./eunit_tests/", [eunit_SUITE]}.
{suites, "./common_tests/suites/", [
        admin_ok_script_SUITE,
        customer_ok_SUITE,
        admin_fail_SUITE
    ]
}.
{cover, "test.coverspec"}.