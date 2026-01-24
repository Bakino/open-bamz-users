# open-bamz-users
Open BamZ users plugin


SELECT has_function_privilege('my_pool_expert_readonly', 'users.user_read()', 'EXECUTE');
SELECT has_schema_privilege('my_pool_expert_readonly', 'users', 'USAGE');
SELECT has_function_privilege('my_pool_expert_admin', 'users.users.role_table_list_permissions()', 'EXECUTE');

GRANT USAGE ON SCHEMA users TO my_pool_expert_readonly;
GRANT EXECUTE ON FUNCTION users.user_read() TO my_pool_expert_readonly;

SELECT 
    n.nspname AS schema_name,
    (aclexplode(n.nspacl)).grantee::regrole AS role_name,
    (aclexplode(n.nspacl)).privilege_type AS privilege
FROM 
    pg_namespace n
WHERE 
    n.nspname = 'users';