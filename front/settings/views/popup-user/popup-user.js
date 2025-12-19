/* Javascript */

view.loader = async ()=>{

    let data = {} ;

    if(view.route.params.login){
        data = await dbApi.db.users.user.getByLogin(view.route.params.login) ;
    }else{
        data.input_password = true;
    }
    data.roles = await dbApi.db.users.role.search({}, {orderBy: ['DISPLAY_ORDER_ASC']});

    return data
}

view.validate = async ()=>{
    if(bootstrap.validateForm(view.querySelector("form"))){
        if(view.route.params.login){
            let update = {
                email: view.data.email,
                active: view.data.active,
                role: view.data.role,
            } ;
            if(view.data.input_password){
                update.password = view.data.password ;
            }
            await dbApi.db.users.user.updateByLogin(view.route.params.login, update) ;
        }else{
            await dbApi.db.users.user.create({
                login: view.data.login,
                email: view.data.email,
                active: view.data.active,
                role: view.data.role,
                password: view.data.password,
            }) ;
        }
        view.closePopup() ;
    }
}