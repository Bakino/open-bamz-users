declare interface UserData {
    /**
     * The login of the user.
     */
    login: string;

    /**
     * The email of the user.
     */
    email: string;

    /**
     * The password of the user (write only)
     */
    password?: string;

    /**
     * The role of the user (default roles are user, readonly, admin).
     */
    role?: string;

    /**
     * True if the user is active, false otherwise.
     */
    active?: boolean;

    /**
     * The activation token of the user (given on creation if active_on_creation setting is false).
     */
    activation_token?: string;
}

/**
 * UsersClient class provides methods to interact with user-related operations
 * such as creating, authenticating, and managing user accounts.
 */
declare class UsersClient {
    /**
     * Constructs a new UsersClient instance.
     * 
     * @param graphqlClient - The GraphQL client used to perform API requests.
     */
    constructor(graphqlClient: any);

    /**
     * Create a new user.
     * 
     * This is allowed only if the setting `public_creation` is set to true.
     * The user will be active depending on the setting `active_on_creation`.
     * If the setting is false, an activation_token will be returned in the user data that you can use to activate the user.
     * The role applied to the user is the one defined in the setting `role_on_public_creation` (default is `user`).
     * 
     * @param user - The user to create (must have at least login, email, and password).
     * @returns A promise that resolves to the created user.
     */
    createUser(user: UserData): Promise<UserData>;

    /**
     * Authenticate a user.
     * 
     * @param login - Login of the user.
     * @param password - Password of the user.
     * @returns A promise that resolves to true if the user is authenticated, false otherwise.
     */
    authenticateUser(login: string, password: string): Promise<boolean>;

    /**
     * Refresh the current user token.
     * 
     * @returns A promise that resolves to true if the token is valid, false otherwise.
     */
    refreshToken(): Promise<boolean>;

    /**
     * Logout the current user.
     */
    logoutUser(): void;

    /**
     * Change the password of the current user.
     *
     * @param oldPassword - The old password.
     * @param newPassword - The new password.
     * @returns A promise that resolves to true if the password is changed, false otherwise.
     */
    changePassword(oldPassword: string, newPassword: string): Promise<boolean>;

    /**
     * Get the current user.
     * 
     * @returns A promise that resolves to the current user data.
     */
    getCurrentUser(): Promise<UserData>;

    /**
     * Update the current user.
     * 
     * `login`, `password`, `active`, and `role` are not updatable.
     * 
     * @param userInformation - The user information to update.
     * @returns A promise that resolves to the updated user.
     */
    updateCurrentUser(userInformation: UserData): Promise<UserData>;

    /**
     * Activate a user from a token.
     * 
     * If you add the setting `active_on_creation` to false, the createUser method will return an `activation_token` that you can use to activate the user.
     * Usually, the user will receive an email with a link to activate containing the token in URL.
     * 
     * @param activationToken - The activation token.
     * @returns A promise that resolves to true if the user is activated, false otherwise.
     */
    activateUser(activationToken: string): Promise<boolean>;

    /**
     * Activate a user from a login and a code.
     * 
     * If you add the setting `active_on_creation` to false, the createUser method will return an `activation_token` that you can use to activate the user.
     * Usually, the user will receive an email with a link to activate containing the token in URL.
     * 
     * @param login - The user login.
     * @param activationCode - The activation code.
     * @returns A promise that resolves to true if the user is activated, false otherwise.
     */
    activateUserByCode(login: string, activationCode: string): Promise<boolean>;


    /**
     * Request a password reset from the user email.
     * 
     * If you add the settings `allow_reset_password` to true, the user is allowed to request a password reset from its email.
     * This function will return a reset token that you can use to reset the password.
     * 
     * @param email - The email of the user.
     * @returns A promise that resolves to the reset token.
     */
    requestPasswordReset(email: string): Promise<string>;

    /**
     * Reset the password of a user.
     * 
     * If you add the settings `allow_reset_password` to true, the user is allowed to request a password reset from its email.
     * 
     * @param resetToken - The reset token (sent to user using requestPasswordReset).
     * @param newPassword - The new password.
     * @returns A promise that resolves to true if the password is reset, false otherwise.
     */
    resetPassword(resetToken: string, newPassword: string): Promise<boolean>;
}
