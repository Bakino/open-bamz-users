import { getUsersClient } from "./users-lib.mjs";

export default {
    globals: {
        usersApi: await getUsersClient()
    }
}
