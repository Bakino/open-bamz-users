import {readFile} from 'fs/promises';
import express from 'express';
import jwt from 'jsonwebtoken';
import {randomBytes} from 'crypto';

/**
 * Called on each application startup (or when the plugin is enabled)
 * 
 * Use it to prepare the database and files needed by the plugin
 */
export const prepareDatabase = async ({options, client, grantSchemaAccess}) => {
    await client.query(`CREATE EXTENSION  IF NOT EXISTS  pgcrypto`);

    //console.log(`CREATE SCHEMA IF NOT EXISTS users`);
    await client.query(`CREATE SCHEMA IF NOT EXISTS users`);
    
    // Settings
    await client.query(`CREATE TABLE IF NOT EXISTS users.settings(
        id int PRIMARY KEY,
        public_creation boolean DEFAULT false,      -- if true, user can subscribe freely
        role_on_public_creation varchar DEFAULT 'user',   -- the role to apply to public creation
        active_on_creation boolean DEFAULT false,   -- if true, user is active on creation
        allow_reset_password boolean DEFAULT false, -- if true, user can reset password from email
        message_template_activation text,          -- the message template to use for activation
        message_template_password_reset text,       -- the message template to use for password reset
        access_token_ttl_minutes integer,          -- access token time to live in minutes
        refresh_token_ttl_minutes integer,         -- refresh token time to live in minutes
        activation_token_ttl_minutes integer,      -- activation token time to live in minutes
        activation_token_type text,                -- activation token type: uuid or code
        activation_token_length integer,           -- activation token length when using code type
        reset_password_token_ttl_minutes integer   -- reset password token time to live in minutes
    )`);


    await client.query(`INSERT INTO users.settings(id, public_creation, role_on_public_creation, active_on_creation, allow_reset_password)
        SELECT 1, false, 'user', false, false
        WHERE NOT EXISTS (SELECT * FROM users.settings)`);


    // Role table 
    await client.query(`CREATE TABLE IF NOT EXISTS users.role(
        role text PRIMARY KEY,
        display_order int DEFAULT 0
    )`);

    // Insert default roles
    console.log(`INSERT INTO users.role(role)`);
    await client.query(`INSERT INTO users.role(role, display_order)
        SELECT * FROM (SELECT 'anonymous', 0
        UNION SELECT 'readonly', 1
        UNION SELECT 'user', 2
        UNION SELECT 'admin', 3) AS r
        WHERE NOT EXISTS (SELECT * FROM users.role)`);

    // Create trigger to create role
    await client.query(`CREATE OR REPLACE FUNCTION users.create_role_trigger()
        RETURNS trigger AS $$
            if(!["anonymous","readonly","user","admin"].includes(NEW.role)){
              //custom role
              const currentDatabase = plv8.execute("SELECT current_database() as current_database", [])[0].current_database;
              plv8.execute(\`CREATE ROLE "\${currentDatabase}_\${NEW.role}" WITH NOLOGIN\`);
            }
            if(!NEW.display_order){
                let max_order = plv8.execute("SELECT max(display_order) as max from users.role", [])[0].max;
                if(!max_order){
                    max_order = 0;
                }
                NEW.display_order = max_order + 1;
            }
            return NEW;
        $$ LANGUAGE plv8 security definer`);

    await client.query(`CREATE OR REPLACE TRIGGER users_create_role_before_insert
        BEFORE INSERT ON users.role
        FOR EACH ROW
        EXECUTE FUNCTION users.create_role_trigger()`);

    // Create trigger to delete role
    await client.query(`CREATE OR REPLACE FUNCTION users.delete_role_trigger()
        RETURNS trigger AS $$
            if(!["anonymous","readonly","user","admin"].includes(OLD.role)){
                //custom role
                const currentDatabase = plv8.execute("SELECT current_database() as current_database", [])[0].current_database;
                plv8.execute(\`DROP ROLE "\${currentDatabase}_\${OLD.role}"\`);
            }
            return OLD;
        $$ LANGUAGE plv8 security definer`);

    await client.query(`CREATE OR REPLACE TRIGGER users_delete_role
        AFTER DELETE ON users.role
        FOR EACH ROW
        EXECUTE FUNCTION users.delete_role_trigger()`);

    // User table
    console.log(`REATE TABLE IF NOT EXISTS users.user`);
    await client.query(`CREATE TABLE IF NOT EXISTS users.user(
        login text PRIMARY KEY,
        email text UNIQUE,
        role text REFERENCES users.role(role),
        password text,   
        active boolean
    )`);



    await client.query(`CREATE TABLE IF NOT EXISTS users.session (
        _id uuid primary key DEFAULT gen_random_uuid(),
        login text REFERENCES users.user(login) ON DELETE CASCADE,
        create_time timestamp without time zone DEFAULT now(),
        token varchar(1024) UNIQUE,
        revoked boolean DEFAULT false,
        expire_time timestamp without time zone
    )`);

    await client.query(`DO $$ BEGIN
            CREATE TYPE users.token_type AS ENUM ('activation', 'password_reset') ;
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;`);
    await client.query(`CREATE TABLE IF NOT EXISTS users.user_token(
        _id uuid primary key DEFAULT gen_random_uuid(),
        create_time timestamp without time zone DEFAULT now(),
        type users.token_type,
        token text,
        login text REFERENCES users.user(login) ON DELETE CASCADE,
        expire timestamp without time zone,
        used_time timestamp without time zone
    )`);


     // Create trigger to send token message
     await client.query(`CREATE OR REPLACE FUNCTION users.token_message_trigger()
        RETURNS trigger AS $$

            const settings = plv8.execute("SELECT * FROM users.settings")[0];
            if(NEW.type === 'activation' && !settings.message_template_activation){
                throw new Error("Activation message template is not set in settings");
            }

            if(NEW.type === 'password_reset' && !settings.message_template_password_reset){
                throw new Error("Password reset message template is not set in settings");
            }
            
            let templateCode ;
            if(NEW.type === 'activation'){
                templateCode = settings.message_template_activation;
            }else if(NEW.type === 'password_reset'){
                templateCode = settings.message_template_password_reset;
            }

            const user = plv8.execute("SELECT * FROM users.user WHERE login = $1", [NEW.login])[0] ;

            plv8.execute("SELECT messages.create_from_template($1, $2)", 
                [templateCode, {user, token: NEW.token, type: NEW.type}]);
            
            return NEW;
        $$ LANGUAGE plv8 security definer`);

    await client.query(`CREATE OR REPLACE TRIGGER user_token_message_insert
        AFTER INSERT ON users.user_token
        FOR EACH ROW
        EXECUTE FUNCTION users.token_message_trigger()`);


    await client.query(`CREATE OR REPLACE FUNCTION users.crypt_password_trigger()
        RETURNS trigger AS $$
            //crypt the password
            if(!OLD || OLD.password !== NEW.password){
                //crypt the password
                const result = plv8.execute("SELECT crypt($1, gen_salt('bf', 12)) as crypted", [NEW.password]);
                NEW.password = result[0].crypted ;
            }
            return NEW;
        $$ LANGUAGE plv8`);

    await client.query(`CREATE OR REPLACE TRIGGER users_create_user_after_insert
        BEFORE INSERT OR UPDATE ON users.user
        FOR EACH ROW
        EXECUTE FUNCTION users.crypt_password_trigger()`);
        
        
    
    //console.log(`CREATE OR REPLACE FUNCTION users.user_authenticate(login text, password text)`);
    await client.query(`CREATE OR REPLACE FUNCTION users.user_authenticate(login text, password text)
RETURNS JSON AS $$
  
    const result = plv8.execute("SELECT *, current_database() as current_database FROM users.user WHERE login = $1 AND password = crypt($2, password) AND active = true", [login, password]);
    if(result.length === 0){
        return null;
    }else{
        const user = result[0] ;
        delete user.password;
        return user;
    }
$$
LANGUAGE plv8 security definer`);



    await client.query(`CREATE OR REPLACE FUNCTION users.user_activate(token text) RETURNS boolean AS $$

            const settings = plv8.execute("SELECT * FROM users.settings")[0];
            if(!settings.public_creation){ return false; }
            if(settings.activation_token_type === "code"){ return false; }

            const result = plv8.execute(\`SELECT * FROM users.user_token WHERE 
                token = $1 AND type = 'activation' AND (expire is NULL or expire > now()) AND used_time IS NULL\`, [token]);

            if(result.length === 0){
                return false;
            }

            plv8.execute(\`UPDATE users.user SET active = true WHERE login = $1\`, [result[0].login]);

            plv8.execute(\`UPDATE users.user_token SET used_time = now() WHERE token = $1\`, [token]);
            return true;
        $$
    LANGUAGE plv8 security definer`);

    await client.query(`CREATE OR REPLACE FUNCTION users.user_activate_code(login text, token text) RETURNS boolean AS $$

            const settings = plv8.execute("SELECT * FROM users.settings")[0];
            if(!settings.public_creation){ return false; }
            if(settings.activation_token_type !== "code"){ return false; }

            const result = plv8.execute(\`SELECT * FROM users.user_token WHERE 
                token = $1 AND login = $2 AND type = 'activation' AND (expire is NULL or expire > now()) AND used_time IS NULL\`, [token, login]);

            if(result.length === 0){
                return false;
            }

            plv8.execute(\`UPDATE users.user SET active = true WHERE login = $1\`, [result[0].login]);

            plv8.execute(\`UPDATE users.user_token SET used_time = now() WHERE token = $1\`, [token]);
            return true;
        $$
    LANGUAGE plv8 security definer`);

    await client.query(`DROP FUNCTION IF EXISTS users.password_reset_request`);
    await client.query(`CREATE OR REPLACE FUNCTION users.password_reset_request(email text) RETURNS boolean AS $$
            // check settings
            const settings = plv8.execute("SELECT * FROM users.settings")[0];
            if(!settings.allow_reset_password){
                throw new Error("Password reset is not allowed");
            }

            const result = plv8.execute(\`SELECT * FROM users.user WHERE 
                email = $1 AND active = true\`, [email]);

            if(result.length === 0){
                return false;
            }

            const expireInMinutes = settings.reset_password_token_ttl_minutes || 180 ; // default 3 hours

            const resultInsert = plv8.execute(\`INSERT INTO users.user_token(type, token, login, expire) 
                VALUES ('password_reset', gen_random_uuid(), $1, now() + interval '\${expireInMinutes} minute')\`, [result[0].login]);
            return true;
        $$
    LANGUAGE plv8 security definer`);

    await client.query(`CREATE OR REPLACE FUNCTION users.password_reset_apply(token text, new_password text) RETURNS boolean AS $$
            const settings = plv8.execute("SELECT * FROM users.settings")[0];
            if(!settings.allow_reset_password){
                throw new Error("Password reset is not allowed");
            }

            const result = plv8.execute(\`SELECT * FROM users.user_token WHERE 
                token = $1 AND type = 'password_reset' AND (expire is NULL or expire > now()) AND used_time IS NULL\`, [token]);

            if(result.length === 0){
                return false;
            }

            plv8.execute(\`UPDATE users.user SET password = $1 WHERE login = $2\`, [new_password, result[0].login]);
            plv8.execute(\`UPDATE users.user_token SET used_time = now() WHERE token = $1\`, [token]);

            return true;
        $$
    LANGUAGE plv8 security definer`);


    //function to change password
    await client.query(`CREATE OR REPLACE FUNCTION users.password_change(old_password text, new_password text) RETURNS boolean AS $$
            const result = plv8.execute(\`SELECT * FROM users.user WHERE 
                login = current_setting('jwt.user_'||current_database()||'.login') AND password = crypt($1, password) AND active = true\`, [old_password]);

            if(result.length === 0){
                return false;
            }

            plv8.execute(\`UPDATE users.user SET password = $1 WHERE login = current_setting('jwt.user_'||current_database()||'.login')\`, [new_password]);
            return true;
        $$
    LANGUAGE plv8 security definer`);

    //function to update data
    await client.query(`CREATE OR REPLACE FUNCTION users.update_user(user_data JSON) RETURNS JSON AS $$
            const result = plv8.execute(\`SELECT * FROM users.user WHERE 
                login = current_setting('jwt.user_'||current_database()||'.login') AND active = true\`, []);

            if(result.length === 0){
                return false;
            }

            delete user_data.login;
            delete user_data.password;
            delete user_data.active;
            delete user_data.role;

            const keys = Object.keys(user_data); 
            const updateResult = plv8.execute(\`UPDATE users.user SET \${keys.map((k, i)=>'"'+k+'" = $'+(i+1)).join(",")}
                WHERE login = current_setting('jwt.user_'||current_database()||'.login') RETURNING *\`, keys.map((k)=>user_data[k]));

            delete updateResult[0].password;

            return updateResult[0];
        $$
    LANGUAGE plv8 security definer`);

    //function to read user
    await client.query(`CREATE OR REPLACE FUNCTION users.user_read() RETURNS users.user AS $$
            const user = plv8.execute(\`SELECT * FROM users.user WHERE login = current_setting('jwt.user_'||current_database()||'.login')\`)[0];
            user.password = null;
            return user;
        $$
    LANGUAGE plv8 security definer`);

    //function to create user
    await client.query(`CREATE OR REPLACE FUNCTION users.user_create(user_data JSON) RETURNS JSON AS $$
            if(!user_data.login || !user_data.email || !user_data.password){
                throw new Error("login, email and password are required");
            }

            //check settings accept user creation
            const settings = plv8.execute("SELECT * FROM users.settings")[0];
            if(!settings.public_creation){
                throw new Error("User creation is not allowed");
            }
            const active = settings.active_on_creation;

            user_data.role = settings.role_on_public_creation;
            user_data.active = active;

            const existingUsers = plv8.execute("SELECT * FROM users.user WHERE login = $1 OR email = $2", [user_data.login, user_data.email]);

            if(existingUsers.length > 0){
                if(existingUsers.length === 1 && 
                    existingUsers[0].login === user_data.login && existingUsers[0].email === user_data.email &&
                    existingUsers[0].active === false){
                    // already exists but not active, we can delete it and recreate
                    plv8.execute("DELETE FROM users.user WHERE login = $1", [user_data.login]);
                }else{
                    throw new Error("ALREADY_EXISTS");
                }
            }


            const keys = Object.keys(user_data); 
            const insertResult = plv8.execute(\`INSERT INTO users.user(\${keys.join(",")}) 
                VALUES(\${keys.map((k,i)=>"$"+(i+1)).join(",")}) RETURNING *\`, keys.map((k)=>user_data[k]));

            delete insertResult[0].password;

            const returnData = {
                ...insertResult[0]
            };

            if(!active){
                let tokenGen = ''
                if(settings.activation_token_type === "code"){
                    const tokenLength = settings.activation_token_length || 6 ;
                    const characters = '0123456789';
                    for ( let i = 0; i < tokenLength; i++ ) {
                        tokenGen += characters.charAt(Math.floor(Math.random() * characters.length));
                    }
                    tokenGen = \`'\${tokenGen}'\` ;
                }
                const expireInMinutes = settings.activation_token_ttl_minutes || 180 ; // default 3 hours
                const resultInsert = plv8.execute(\`INSERT INTO users.user_token(type, token, login, expire) 
                    VALUES ('activation', \${tokenGen}, $1, now() + interval '\${expireInMinutes} minute') RETURNING token\`, [user_data.login]);
            }

            return returnData;
        $$
    LANGUAGE plv8 security definer`);


    await client.query(`CREATE OR REPLACE FUNCTION users.role_table_list_permissions() RETURNS JSON AS $$

            const currentDatabase = plv8.execute("SELECT current_database() as current_database")[0].current_database;

            const roles = plv8.execute(\`SELECT rolname FROM pg_roles
                WHERE rolname='anonymous' OR (rolname NOT LIKE 'pg_%' and rolname <> 'postgres' and rolname LIKE current_database() || '_%')\`);

            const result = plv8.execute(\`SELECT
                table_schema,
                table_name,
                grantee as role_name,
                privilege_type
            FROM
                information_schema.table_privileges
            WHERE
                grantee IN (
                    SELECT rolname FROM pg_roles
                    WHERE  rolname='anonymous' OR (rolname NOT LIKE 'pg_%' and rolname <> 'postgres' and rolname LIKE current_database() || '_%')
                )\`);    

            const permissions = {};
            for(let row of result){
                const fullTable = row.table_schema+"_"+row.table_name;
                if(!permissions[fullTable]){
                    permissions[fullTable] = {
                        table_schema: row.table_schema,
                        table_name: row.table_name,
                        permissions: [
                            { permission: "DELETE", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                            { permission: "INSERT", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                            { permission: "REFERENCES", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                            { permission: "SELECT", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                            { permission: "TRIGGER", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                            { permission: "TRUNCATE", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                            { permission: "UPDATE", roles: roles.map((r)=>({ role: r.rolname.replace(currentDatabase+"_", ""), allowed: false})) },
                        ]
                    };
                }
                permissions[fullTable].permissions
                    .find((r)=>r.permission === row.privilege_type).roles
                        .find((r)=>r.role === row.role_name.replace(currentDatabase+"_", "")).allowed = true;
            }
            return Object.values(permissions);
        $$
    LANGUAGE plv8`);


    await client.query(`CREATE OR REPLACE FUNCTION users.role_table_set_permissions(table_schema TEXT, table_name TEXT, role_name TEXT, permissions TEXT) RETURNS VOID AS $$
            let roleName = role_name;
            if(roleName !== "anonymous"){
                const currentDatabase = plv8.execute("SELECT current_database() as current_database")[0].current_database;
                roleName = currentDatabase+"_"+roleName;
            }

            plv8.execute(\`GRANT \${permissions} ON TABLE \${table_schema}.\${table_name} TO \${roleName}\`);
        $$
    LANGUAGE plv8`);

    await client.query(`CREATE OR REPLACE FUNCTION users.role_table_remove_permissions(table_schema TEXT, table_name TEXT, role_name TEXT, permissions TEXT) RETURNS VOID AS $$
            let roleName = role_name;
            if(roleName !== "anonymous"){
                const currentDatabase = plv8.execute("SELECT current_database() as current_database")[0].current_database;
                roleName = currentDatabase+"_"+roleName;
            }
            
            plv8.execute(\`REVOKE \${permissions} ON TABLE \${table_schema}.\${table_name} FROM \${roleName}\`);
        $$
    LANGUAGE plv8`);


    await client.query(`CREATE OR REPLACE FUNCTION users.policies_list() RETURNS JSON AS $$
            const result = plv8.execute(\`SELECT * FROM pg_policies\`);
            if(result.length === 0){
                return [];
            }
            const currentDatabase = plv8.execute("SELECT current_database() as current_database")[0].current_database;
            const checkActivatedResult = plv8.execute(\`select n.nspname, relname, relrowsecurity, relforcerowsecurity
                    from pg_class join pg_catalog.pg_namespace n on n.oid = pg_class.relnamespace
                    where  relkind = 'r' and relname in (\${result.map(r=>"'"+r.tablename+"'").join(",")})\`);
            const policies = {};
            for(let row of result){
                const fullTable = row.schemaname+"_"+row.tablename;
                if(!policies[fullTable]){
                    policies[fullTable] = {
                        table_schema: row.schemaname,
                        table_name: row.tablename,
                        policies: [],
                        row_security_active: checkActivatedResult.find(r=>r.nspname === row.schemaname && r.relname === row.tablename)?.relrowsecurity,
                        force_row_security_active: checkActivatedResult.find(r=>r.nspname === row.schemaname && r.relname === row.tablename)?.relforcerowsecurity
                    };
                }
                policies[fullTable].policies.push({
                    policy_name: row.policyname,
                    roles: row.roles.map(r=>r.replace(currentDatabase+"_", "")),
                    cmd: row.cmd,
                    qual: row.qual,
                    with_check: row.with_check
                });
            }
            
            return Object.values(policies);
        $$
    LANGUAGE plv8`);

    await client.query(`CREATE OR REPLACE FUNCTION users.policy_add(table_schema TEXT, table_name TEXT, policy_name TEXT, role_name TEXT, condition TEXT) RETURNS VOID AS $$
            let roleName = role_name;
            if(roleName !== "anonymous"){
                const currentDatabase = plv8.execute("SELECT current_database() as current_database")[0].current_database;
                roleName = currentDatabase+"_"+roleName;
            }

            plv8.execute(\`ALTER TABLE \${table_schema}.\${table_name} ENABLE ROW LEVEL SECURITY\`);
            
            plv8.execute(\`CREATE POLICY \${policy_name} ON \${table_schema}.\${table_name} TO \${roleName} USING (\${condition})\`);
        $$
    LANGUAGE plv8`); 

    await client.query(`CREATE OR REPLACE FUNCTION users.policy_enable(table_schema TEXT, table_name TEXT) RETURNS VOID AS $$
            plv8.execute(\`ALTER TABLE \${table_schema}.\${table_name} ENABLE ROW LEVEL SECURITY\`);            
        $$
    LANGUAGE plv8`);
    await client.query(`CREATE OR REPLACE FUNCTION users.policy_disable(table_schema TEXT, table_name TEXT) RETURNS VOID AS $$
            plv8.execute(\`ALTER TABLE \${table_schema}.\${table_name} DISABLE ROW LEVEL SECURITY\`);            
        $$
    LANGUAGE plv8`);

    await client.query(`CREATE OR REPLACE FUNCTION users.policy_remove(table_schema TEXT, table_name TEXT, policy_name TEXT) RETURNS VOID AS $$
            plv8.execute(\`DROP POLICY \${policy_name} ON \${table_schema}.\${table_name}\`);
        $$
    LANGUAGE plv8`);



    await grantSchemaAccess("users"); ;

    //console.log(`GRANT USAGE ON SCHEMA users TO anonymous`);
    await client.query(`GRANT USAGE ON SCHEMA users TO anonymous`);
    //console.log(`GRANT EXECUTE ON FUNCTION users.user_authenticate TO anonymous`);

    for(let role of ["anonymous",`${options.database}_readonly`,`${options.database}_user`,`${options.database}_admin`]){
        await client.query(`GRANT EXECUTE ON FUNCTION users.user_authenticate TO ${role}`);
        // await client.query(`GRANT EXECUTE ON FUNCTION users.user_refresh TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.password_reset_request TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.password_reset_apply TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.user_activate TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.password_change TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.user_read TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.user_create TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.update_user TO ${role}`);
    }
    for(let role of [`${options.database}_admin`]){
        await client.query(`GRANT EXECUTE ON FUNCTION users.role_table_list_permissions TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.role_table_set_permissions TO ${role}`);
        await client.query(`GRANT EXECUTE ON FUNCTION users.role_table_remove_permissions TO ${role}`);
    }


    //console.log(`GRANT EXECUTE ON FUNCTION users.user_refresh TO anonymous`);
    //await client.query(`REVOKE EXECUTE ON FUNCTION users.user_create FROM public`);



    /*await client.query(`GRANT SELECT ON ALL TABLES IN SCHEMA publicusers TO anonymous`);

    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA publicusers GRANT SELECT ON TABLES TO anonymous`);
    await client.query(`ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA publicusers GRANT SELECT ON TABLES TO anonymous`);*/
}

/**
 * Called when the plugin is disabled
 * 
 * Use it to eventually clean the database and files created by the plugin
 */
export const cleanDatabase = async ({client}) => {
    await client.query(`DROP SCHEMA IF EXISTS users CASCADE`);
}


/**
 * Init plugin when Open BamZ platform start
 */
export const initPlugin = async ({ loadPluginData, runQuery }) => {
    const router = express.Router();

    const PRIVATE_KEY = await readFile(process.env.JWT_PRIVATE_KEY_FILE);

    function generateToken() {
        return randomBytes(48).toString('hex');
    }

    function signAccessToken(payload, expireMinutes) {
        return jwt.sign(payload, PRIVATE_KEY, {
            algorithm: 'RS256',
            expiresIn: expireMinutes+'m',
            audience: 'bamz-api',
            issuer: 'bamz',
        });
    }

    async function saveSession(appName, userId, token, expiresAt) {
        await runQuery({database: appName}, `INSERT INTO users.session (account_id, token, expire_time, revoked) VALUES ($1, $2, $3, false)
            ON CONFLICT (token) DO UPDATE SET expire_time = $3, revoked = false`, [userId, token, expiresAt])
    }

    async function revokeSession(appName, token) {
        await runQuery({database: appName},`UPDATE users.session SET revoked = true WHERE token = $1`, [token]);
    }

    async function findSession(appName, token) {
        const result = await runQuery({database: appName}, `SELECT account_id, token, expire_time, revoked FROM users.session WHERE token = $1`, [token]);
        if (result.rows.length === 0) return null;
        return result.rows[0];
    }

    async function authenticateUser(appName, email, password) {
        let result = await runQuery({database: appName}, `SELECT users.user_authenticate(($1, $2) as account`, [email, password]) ;
        if(result.rows.length>0){
            return result.rows[0].account ;
        }
        return null;
    }
    async function readUser(appName, login) {
        let result = await runQuery({database: appName}, `SELECT * FROM users.user WHERE login = $1 and active = true`, [login]) ;
        if(result.rows.length>0){
            return result.rows[0] ;
        }
        return null;
    }

    async function genSession(user, req, res){
        let access_token_ttl_minutes = 3 * 60 ; // default 3h
        let refresh_token_ttl_minutes = 3 * 24 * 60 // default 3 days
        let resultSettings = await runQuery({database: req.appName}, `SELECT users.settings`, []) ;
        if(resultSettings.rows.length>0){
            if(resultSettings.access_token_ttl_minutes){
                access_token_ttl_minutes = resultSettings.access_token_ttl_minutes ;
            }
            if(resultSettings.refresh_token_ttl_minutes){
                refresh_token_ttl_minutes = resultSettings.refresh_token_ttl_minutes ;
            }
        }

        const accessToken = signAccessToken(user , access_token_ttl_minutes);

        // create refresh token
        const refreshToken = generateToken();
        const expiresAt = new Date(Date.now() + access_token_ttl_minutes * 60 * 1000);
        await saveSession(req.appName, user.login, refreshToken, expiresAt);

        // set cookies
        res.cookie(`jwt-user_${req.appName}-access`, accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            domain: process.env.COOKIE_DOMAIN || ".test3.bakino.fr",
            maxAge: access_token_ttl_minutes * 60 * 1000
        });

        res.cookie(`jwt-user_${req.appName}-refresh`, refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            domain: process.env.COOKIE_DOMAIN || ".test3.bakino.fr",
            maxAge: refresh_token_ttl_minutes * 60 * 1000
        });
    }


    router.post('/login', express.json(), async (req, res) => {
        const { email, password } = req.body;

        const user = await authenticateUser(req.appName, email, password);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        genSession(user, req, res)
        

        res.json({ ok: true });
    });

    router.post('/refresh', async (req, res) => {
        const oldToken = req.cookies?.[`jwt-user_${req.appName}-refresh`];
        if (!oldToken) return res.status(401).end();

        const entry = await findSession(req.appName, oldToken);
        if (!entry || entry.revoked || entry.expire_time < new Date()) {
            return res.status(401).end();
        }
        await revokeSession(req.appName, oldToken);

        const user = await readUser(req.appName, entry.login);
        if(!user){
            return res.status(401).end();
        }
        await genSession(user, req, res)

        res.json({ ok: true });
    });


    router.post('/logout', async (req, res) => {
        const rt = req.cookies?.refresh_token;
        if (rt) await revokeSession(req.appName, rt);

        res.clearCookie(`jwt-user_${req.appName}-access`);
        res.clearCookie(`jwt-user_${req.appName}-refresh`);
        res.json({ ok: true });
    });


    loadPluginData(async ({pluginsData})=>{
        if(pluginsData?.["open-bamz-viewz"]?.pluginSlots?.viewzExtensions){
            pluginsData?.["open-bamz-viewz"]?.pluginSlots?.viewzExtensions.push( {
                plugin: "users",
                extensionPath: "/plugin/open-bamz-users/lib/viewz-users.mjs",
                "d.ts": `declare const usersApi: UsersClient;`
            })
        }
        if(pluginsData?.["code-editor"]?.pluginSlots?.javascriptApiDef){
            pluginsData?.["code-editor"]?.pluginSlots?.javascriptApiDef.push( {
                plugin: "users",
                url: "/plugin/open-bamz-users/lib/users-lib.d.ts"
            })
        }
    })

    return {
        // path in which the plugin provide its front end files
        frontEndPath: "front",
        //lib that will be automatically load in frontend
        frontEndPublic: "lib",
        frontEndLib: "lib/users-lib.mjs",
        router: router,
        //menu entries
        menu: [
            {
                name: "admin", entries: [
                    { name: "Users Settings", link: "/plugin/open-bamz-users/settings/index.html" }
                ]
            }
        ]
    }
}