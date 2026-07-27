import express from "express";
import pg from "pg";
import path from "node:path";
import os from "node:os";
import { mkdtemp, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";

// RS256 keypair for JWT — written to temp files, referenced via env BEFORE init.
const keydir = await mkdtemp(path.join(os.tmpdir(), "users-jwt-"));
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
await writeFile(path.join(keydir, "priv.pem"), privateKey);
await writeFile(path.join(keydir, "pub.pem"), publicKey);
process.env.JWT_PRIVATE_KEY_FILE = path.join(keydir, "priv.pem");
process.env.JWT_PUBLIC_KEY_FILE = path.join(keydir, "pub.pem");
// Cookie `domain` can't contain a port; prod sets COOKIE_DOMAIN, so does the test.
process.env.COOKIE_DOMAIN = "localhost";

const { createBamz } = await import("openbamz-lib");
const plugin = (await import("./index.mjs")).default;

const PORT = 58414;
const DB = "bamztest";
let failures = 0;
function assert(cond, msg) {
    if (!cond) { failures++; console.error("FAIL:", msg); }
    else { console.log("PASS:", msg); }
}
function slotStub(name, slotNames) {
    const slots = {};
    for (const s of slotNames) slots[s] = [];
    return { plugin: { name, async init() { return { pluginSlots: slots }; } }, slots };
}
async function gql(query, headers = {}) {
    const res = await fetch(`http://localhost:${PORT}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ query }),
    });
    return res.json();
}

async function main() {
    const pool = new pg.Pool({ host: "localhost", port: 55432, user: "postgres", password: "openbamz", database: DB });

    await pool.query(`DROP SCHEMA IF EXISTS users CASCADE`);

    const bamz = createBamz({ db: { host: "localhost", port: 55432, user: "postgres", password: "openbamz", database: DB }, watch: false });
    const viewz = slotStub("open-bamz-viewz", ["viewzExtensions"]);
    const codeEditor = slotStub("open-bamz-code-editor", ["javascriptApiDef"]);
    bamz.use(plugin);
    bamz.use(viewz.plugin);
    bamz.use(codeEditor.plugin);

    await bamz.init();
    console.log("init() succeeded");
    const app = express();
    await bamz.mount(app);
    const server = await new Promise((r) => { const s = app.listen(PORT, () => r(s)); });

    const ACCESS = `x-cors-jwt-user_${DB}-access`;
    const REFRESH = `x-cors-jwt-user_${DB}-refresh`;

    try {
        // 1. schema objects
        {
            const { rows } = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='users' ORDER BY 1`);
            const t = rows.map((r) => r.table_name);
            assert(["auth_providers", "role", "session", "settings", "user", "user_token"].every((x) => t.includes(x)),
                `users tables present (got ${JSON.stringify(t)})`);
            const { rows: roles } = await pool.query(`SELECT role FROM users.role ORDER BY display_order`);
            assert(roles.map((r) => r.role).join(",") === "anonymous,readonly,user,admin", `default roles seeded (got ${JSON.stringify(roles.map(r => r.role))})`);
        }

        // 1b. core provisioned the anonymous role + the app roles
        {
            const { rows } = await pool.query(`SELECT rolname FROM pg_roles WHERE rolname IN ('anonymous','${DB}_user','${DB}_admin') ORDER BY 1`);
            assert(rows.length === 3, `anonymous + app roles exist (got ${JSON.stringify(rows.map(r => r.rolname))})`);
        }

        // 2. create an active user (crypt trigger hashes the password)
        await pool.query(`INSERT INTO users.user(login,email,name,role,password,active) VALUES('alice','alice@x.com','Alice','user','secret',true)
                          ON CONFLICT (login) DO UPDATE SET password='secret', active=true`);
        {
            const { rows } = await pool.query(`SELECT password FROM users.user WHERE login='alice'`);
            assert(rows[0].password !== "secret" && rows[0].password.startsWith("$2"), `crypt_password_trigger bcrypt-hashed the password`);
        }

        // 3. LOGIN (x-cors mode returns tokens as response headers)
        let access, refresh;
        {
            const res = await fetch(`http://localhost:${PORT}/open-bamz-users/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "x-cors-auth": "1" },
                body: JSON.stringify({ login: "alice", password: "secret" }),
            });
            const body = await res.json();
            access = res.headers.get(ACCESS);
            refresh = res.headers.get(REFRESH);
            assert(res.status === 200 && body.ok === true, `POST /login ok (status ${res.status})`);
            assert(!!access && !!refresh, `login returned x-cors access+refresh tokens`);
            const { rows } = await pool.query(`SELECT login, revoked FROM users.session WHERE token=$1`, [refresh]);
            assert(rows.length === 1 && rows[0].login === "alice" && rows[0].revoked === false, `session row persisted for alice`);
        }

        // 3b. wrong password -> 401
        {
            const res = await fetch(`http://localhost:${PORT}/open-bamz-users/login`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ login: "alice", password: "wrong" }),
            });
            assert(res.status === 401, `POST /login wrong password -> 401 (got ${res.status})`);
        }

        // 4. THE CRUX: authenticated GraphQL runs under the user's role WITH the
        //    login GUC. password_change() reads current_setting('jwt.user_<db>.login')
        //    to find the current user -> returns true and actually changes the pw.
        {
            const authHeaders = { [ACCESS]: access, [REFRESH]: refresh };
            const r = await gql(`mutation { users_password_change(input: { old_password: "secret", new_password: "secret2" }) { result } }`, authHeaders);
            assert(!r.errors, `authenticated users_password_change executed without error (${JSON.stringify(r.errors)})`);
            assert(r.data?.users_password_change?.result === true, `password_change returned true under the authenticated role+login GUC (got ${JSON.stringify(r.data)})`);
            // verify the DB effect: new password authenticates, old does not
            const okNew = await pool.query(`SELECT users.user_authenticate('alice','secret2') AS a`);
            const okOld = await pool.query(`SELECT users.user_authenticate('alice','secret') AS a`);
            assert(okNew.rows[0].a && !okOld.rows[0].a, `password actually changed in DB via the authenticated GraphQL call`);
        }

        // 4b. anonymous (no auth headers) cannot change password: login GUC empty -> false
        {
            const r = await gql(`mutation { users_password_change(input: { old_password: "secret2", new_password: "hack" }) { result } }`);
            assert(!r.errors && r.data?.users_password_change?.result === false,
                `anonymous password_change returns false (no login GUC) (got ${JSON.stringify(r.errors || r.data)})`);
        }

        // 5. /logout revokes the session -> /refresh then fails
        {
            const res = await fetch(`http://localhost:${PORT}/open-bamz-users/logout`, {
                method: "POST", headers: { "x-cors-auth": "1", [REFRESH]: refresh },
            });
            assert(res.status === 200, `POST /logout ok (${res.status})`);
            const { rows } = await pool.query(`SELECT revoked FROM users.session WHERE token=$1`, [refresh]);
            assert(rows[0]?.revoked === true, `logout revoked the session in DB`);
            const rf = await fetch(`http://localhost:${PORT}/open-bamz-users/refresh`, {
                method: "POST", headers: { [REFRESH]: refresh },
            });
            assert(rf.status === 401, `refresh after logout -> 401 (got ${rf.status})`);
        }

        // 6. real init()->contribute() wiring
        {
            assert(viewz.slots.viewzExtensions.some((e) => e.extensionPath.endsWith("viewz-users.mjs")), `contributed viewzExtension into viewz`);
            assert(codeEditor.slots.javascriptApiDef.some((e) => e.url.endsWith("users-lib.d.ts")), `contributed javascriptApiDef into code-editor (normalized key)`);
        }
    } finally {
        await new Promise((r) => server.close(r));
        await bamz.close();
        await pool.end();
    }

    console.log(`\n${failures === 0 ? "ALL PASS" : failures + " FAILURE(S)"}`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error("SMOKE TEST CRASHED:", err); process.exit(1); });
