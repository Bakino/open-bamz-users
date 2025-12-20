/* Javascript */

view.loader = async ()=>{

    let data = {} ;

    if(view.route.params.code){
        data = await dbApi.db.users.auth_providers.getByCode(view.route.params.code) ;
    }

    return data
}

view.validate = async ()=>{
    if(bootstrap.validateForm(view.querySelector("form"))){
        if(view.route.params.code){
            let update = {
                provider_type: view.data.provider_type,
                provider_settings: view.data.provider_settings
            } ;
            await dbApi.db.users.auth_providers.updateByCode(view.route.params.code, update) ;
        }else{
            await dbApi.db.users.auth_providers.create({
                code: view.data.code,
                provider_type: view.data.provider_type,
                provider_settings: view.data.provider_settings
            }) ;
        }
        view.closePopup() ;
    }
}