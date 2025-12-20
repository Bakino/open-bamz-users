declare const usersApi: UsersClient;


interface ViewZ {
    /** 
     * Check if the user is logged in
     * 
     * If not logged, redirect to loginRoute
     * 
     * This is expected to be called in the loader function of a view to protect it
     * @example
     * ```javascript
     * view.loader = async ()=>{
     *    const userData = await view.checkLogged("/myapp/login/:url") ;
     *    
     *    // continue loading data
     *    return { ... } ;
     * }
     * 
     * @param loginRoute The route to redirect if not logged (default: /login/:url)
     * @returns A promise that resolves to user data if the user is logged, false otherwise.
     */
    checkLogged(loginRoute?: string): Promise<UserData>;
}
