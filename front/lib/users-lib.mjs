
/**
 * This class allows you to interact with the users from a user context
 * 
 * You can create, authenticate, and then interact with the current user (change password, update information, etc.)
 * 
 * If you are an admin, you don't need to use this class, you can directly interact with the users.user table
 */
class UsersClient {
    constructor(graphqlClient) {
        this.graphqlClient = graphqlClient;
    }

    /**
     * Create a new user
     * 
     * This is allowed only if the setting `public_creation` is set to true
     * 
     * The user will be active depending on the setting `active_on_creation`. 
     * If the setting is false, an activation_token will be returned in the user data that you can use to activate the user.
     * 
     * The role applied to the user is the one defined in the setting `role_on_public_creation` (default is `user`)
     * 
     * @param {*} user The user to create (must have at least login, email and password)
     * @returns the created user
     */
    async createUser(user) {
        return await this.graphqlClient.mutations.users_user_create({ input: {user_data: user}}) ;
    }
   
   
    /**
     * Authenticate a user
     * 
     * @param {string} login Login of the user
     * @param {string} password Password of the user
     * @returns {Promise<boolean>} true if the user is authenticated, false otherwise
     */
    async authenticateUser(login, password) {
        const response = await fetch("/open-bamz-users/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({login, password})
        }) ;
        if(!response.ok){
            return false ;
        }
        try{
            const result = await response.json() ;
            return result.ok ;
        }catch(err){
            console.warn("Error parsing JSON response", err) ;
            return false ;
        }
    }

    /**
     * Refresh the current user token
     * 
     * @returns {Promise<boolean>} true if the token is valid, false otherwise
     */
    async refreshToken() {
        let response = await fetch("/open-bamz-users/refresh", {
            method: "POST",
            credentials: "include"
        });
        return response.ok ;
    }

    /**
     * Logout the current user
     */
    async logoutUser() {
        let response = await fetch("/open-bamz-users/logout", { method: "POST", credentials: "include" }) ;
        if(!response.ok){
            console.warn("Error during logout", response.statusText) ;
        }
    }

    /**
     * Change the password of the current user
     *
     * @param {string} oldPassword The old password
     * @param {string} newPassword The new password
     * @returns {Promise<boolean>} true if the password is changed, false otherwise
     */
    async changePassword(oldPassword, newPassword) {
        let result = await this.graphqlClient.mutations.users_password_change({input: {old_password: oldPassword, new_password: newPassword}})
        return result
    }

    /**
     * Get the current user
     */
    async getCurrentUser() {
        let result = await this.graphqlClient.mutations.users_user_read({input: {}})
        return result;
    }

    /**
     * Update the current user
     * 
     * `login`, `password`, `active` and `role` are not updatable
     * 
     * @param {*} userInformation The user information to update
     * @returns the updated user
     */
    async updateCurrentUser(userInformation) {
        return await this.graphqlClient.mutations.users_update_user({input: {user_data: userInformation}})
    }

    /**
     * Activate a user from a token
     * 
     * If you add the setting `active_on_creation` to false, the createUser method will return an `activation_token` that you can use to activate the user.
     * 
     * Usually, the user will receive an email with a link to activate containing the token in URL
     * 
     * @param {string} activationToken The activation token
     * @returns {Promise<boolean>} true if the user is activated, false otherwise
     */
    async activateUser(activationToken){
        let result = await this.graphqlClient.mutations.users_user_activate({input: {token: activationToken}})
        return result;
    }

    /**
     * Activate a user from a code token
     * 
     * If you add the setting `active_on_creation` to false, the createUser method will return an `activation_token` that you can use to activate the user.
     * 
     * Usually, the user will receive an email with a link to activate containing the token in URL
     * 
     * @param {string} login The user login
     * @param {string} activationCode The activation token
     * @returns {Promise<boolean>} true if the user is activated, false otherwise
     */
    async activateUserByCode(login, activationCode){
        let result = await this.graphqlClient.mutations.users_user_activate_code({input: {login, token: activationCode}})
        return result;
    }

    /**
     * Request a password reset from the user email
     * 
     * If you add the settings `allow_reset_password` to true, the user is allowed to request a password reset from its email
     * 
     * This function will return a reset token that you can use to reset the password
     * 
     * @param {string} email The email of the user
     * @returns {Promise<string>} The reset token
     */
    async requestPasswordReset(email){
        let result = await this.graphqlClient.mutations.users_password_reset_request({input: {email}})
        return result;
    }

    /**
     * Reset the password of a user
     * 
     * If you add the settings `allow_reset_password` to true, the user is allowed to request a password reset from its email
     * 
     * @param {string} resetToken The reset token (sent to user using requestPasswordReset)
     * @param {string} newPassword The new password
     * @returns {Promise<boolean>} true if the password is reset, false otherwise
     */
    async resetPassword(resetToken, newPassword){
        let result = await this.graphqlClient.mutations.users_password_reset_apply({input: {token: resetToken, new_password: newPassword}})
        return result;
    }

    /**
     * Get the settings of a provider
     * 
     * @param {string} code The code of the provider
     * @returns {Promise<any>} settings of the provider
     */
    async publicAuthProviderSettings(code){
        let result = await this.graphqlClient.mutations.users_public_auth_provider_settings({input: {code}})
        return result;
    }

    /**
     * Load the login button for a provider into an element
     * @param {string} code The code of the provider
     * @param {HTMLElement|string} elementOrId The element or its id where to load the button
     * @param {object} options Options for the button (depends on provider)
     */
    async loadProviderLoginButton(code, elementOrId, options = {}) {
        let settings = await this.publicAuthProviderSettings(code) ;
        if(!settings){
            throw new Error("Auth provider not found") ;
        }
        // @ts-ignore
        if(settings.provider_type === "google"){
            await loadGsiScript() ;
            // @ts-ignore
            if (!window.google) return console.warn('Google library not loaded yet');
            // @ts-ignore
            window.google.accounts.id.initialize({ //https://developers.google.com/identity/gsi/web/reference/js-reference
                // @ts-ignore
                client_id: settings.provider_settings.client_id,
                callback: (response)=>{
                    fetch('/open-bamz-users/auth/provider', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ id_token: response.credential, provider: code })
                    }).then(r => r.json()).then(console.log).catch(console.error);
                },
            });
            if(typeof elementOrId === "string"){
                elementOrId = document.getElementById(elementOrId) ;
            }
            const buttonOptions = { //https://developers.google.com/identity/gsi/web/guides/display-button
                theme: 'outline', 
                size: 'large',
                ...options
            } ;
            // @ts-ignore
            window.google.accounts.id.renderButton(elementOrId,buttonOptions);
        }
    }
}

function loadGsiScript() {
    // @ts-ignore
    if (window.google && window.google.accounts) return Promise.resolve(window.google);
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://accounts.google.com/gsi/client';
        s.async = true;
        s.defer = true;
        // @ts-ignore
        s.onload = () => (window.google && window.google.accounts) ? resolve(window.google) : reject(new Error('GSI loaded but google.accounts missing'));
        s.onerror = (e) => reject(e);
        document.head.appendChild(s);
    });
}

/**
 * Create a UsersClient instance for the given app.
 * 
 * @example
 * const usersClient = await getUsers(); // get current app's users client
 * const usersClient = await getUsers("someApp"); // get someApp's users client
 * const usersClient = await getUsers(graphqlClient); // get users client providing a graphqlClient
 * 
 * @param {*} appNameOrGraphqlClient The name of the app or a graphql client (from dbadmin plugin). Current app is used if not provided.
 * @returns UsersClient instance
 */
export async function getUsersClient(appNameOrGraphqlClient=""){
    if(!appNameOrGraphqlClient){
        // @ts-ignore
        appNameOrGraphqlClient = window.BAMZ_APP ;
    }

    let graphqlClient = appNameOrGraphqlClient ;

    if(appNameOrGraphqlClient.constructor === String){
        // @ts-ignore
        const dbadmin = await window.bamzGetPlugin("dbadmin");
        if(dbadmin){
            // db plugin is already loaded, use it
            graphqlClient =  await dbadmin.getGraphqlClient(appNameOrGraphqlClient) ;
        }else{
            // load db-lib
            // @ts-ignore
            let {getGraphqlClient} = await import("https://cdn.jsdelivr.net/gh/Bakino/open-bamz-database@988f1aaa8c61b436cdab656e507829556c68b742/front/lib/db-lib.mjs") ;
            graphqlClient = await getGraphqlClient(appNameOrGraphqlClient) ;
        }
    }

    return new UsersClient(graphqlClient);
}




