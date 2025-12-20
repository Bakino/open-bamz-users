import { getUsersClient } from "./users-lib.mjs";


const usersApi = await getUsersClient() ;

export default {
    globals: {
        usersApi: usersApi
    },
    extends: {
        checkLogged: async function(loginRoute = "/login/:url"){
            try{
                const refreshed = await usersApi.refreshToken() ;
                if(!refreshed){
                    this.abortRender() ;
                    // @ts-ignore
                    this.router.navigateTo(loginRoute.replace("/:url", "/"+encodeURIComponent(this.router.getCurrentLocation().pathname))) ;
                    return false;
                }
                return await usersApi.getCurrentUser() ;
            }catch(err){
                console.log("refresh token failed", err) ;
                this.abortRender() ;
                // @ts-ignore
                this.router.navigateTo(loginRoute.replace("/:url", "/"+encodeURIComponent(this.router.getCurrentLocation().pathname))) ;
                return false;
            }
        }
    }
}
