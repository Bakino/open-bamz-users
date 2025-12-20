//Script goes here

// @ts-ignore
const {codeToHtml} = await import('https://esm.sh/shiki@3.0.0')


view.loader = async ()=>{

    let logged = await usersApi.refreshToken() ;
    let settings = null;
    let roles = null ;
    let users = null ;
    let message_templates = null;
    let permissions = [] ;
    let policies = [] ;
    let authProviders = [] ;
    if(dbApi.db.users){
        settings = await dbApi.db.users.settings.searchFirst() ;
        roles = await dbApi.db.users.role.search({}, {orderBy: ['DISPLAY_ORDER_ASC']});
        users = await dbApi.db.users.user.search({}, {orderBy: ['LOGIN_ASC']}) ;
        authProviders = await dbApi.db.users.auth_providers.search({}, {orderBy: ['CODE_ASC']}) ;
        try{
            
            const permissionsAllTables = await dbApi.db.users.mutations.role_table_list_permissions();
            for(let perm of permissionsAllTables){
                if(perm.table_schema !== "public"){ continue ; }
                permissions.push({
                    table_schema: perm.table_schema,
                    table_name: perm.table_name,
                    roles : roles.map(r=>{
                        return {
                            role: r.role,
                            permissions: [
                                { role: r.role, table_schema: perm.table_schema, table_name: perm.table_name, permission: "SELECT", 
                                    name: "read",   
                                    allowed: perm.permissions.find(p=>p.permission === "SELECT")?.roles.find(p=>p.role === r.role)?.allowed
                                    },
                                { role: r.role, table_schema: perm.table_schema, table_name: perm.table_name, permission: "INSERT",
                                    name: "insert", 
                                    allowed: perm.permissions.find(p=>p.permission === "INSERT")?.roles.find(p=>p.role === r.role)?.allowed
                                    },
                                { role: r.role, table_schema: perm.table_schema, table_name: perm.table_name, permission: "UPDATE",
                                    name: "update", 
                                    allowed: perm.permissions.find(p=>p.permission === "UPDATE")?.roles.find(p=>p.role === r.role)?.allowed
                                    },
                                { role: r.role, table_schema: perm.table_schema, table_name: perm.table_name, permission: "DELETE",
                                    name: "delete", 
                                    allowed: perm.permissions.find(p=>p.permission === "DELETE")?.roles.find(p=>p.role === r.role)?.allowed
                                    }
                            ]
                        }
                    })
                }) ;

            }

            policies = (await dbApi.db.users.mutations.policies_list()) ;
        }catch(err){
            //not allowed to see permissions
        }
    }

    if(dbApi.db.messages){
        message_templates = await dbApi.db.messages.template.search() ;
    }

    return {
        logged,
        settings,
        authProviders,
        roles,
        users,
        permissions,
        policies,
        message_templates,
    }
}

async function doHighlight(){
    let codeEls = view.querySelectorAll('code[lang]') ;
    for(let codeEl of codeEls){
        if(codeEl.hasAttribute("code-rendered")){
            continue ;
        }
        codeEl.setAttribute("code-rendered", "done") ;
        let lang = codeEl.getAttribute("lang") ; 
        //let comment = Array.prototype.find.call(codeEl.childNodes,n=>n.nodeName === "#comment")
        let comment = Array.prototype.find.call(codeEl.childNodes,n=>n.tagName === "PRE")
        if(comment){
            let codeStr = comment.textContent;//.replace(/^\s*\n+/, "").replace(/\n+\s*$/, "").replace(/!--/g, "<!--").replace(/--!/g, "-->") ; ;
            //let codeStr = codeEl.innerText;

            //remove indentation
            let regexp = new RegExp(/^(\s*)/, "m") ;
            let result = codeStr.match(regexp);
            if(result && result[1]){
                codeStr = codeStr.replace(new RegExp("\n"+result[1]+"", "g"), "\n") ;
            }
            codeStr = codeStr.trim() ;

            let button = document.createElement("BUTTON") ;
            button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard" viewBox="0 0 16 16">
                <path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/>
                <path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/>
            </svg>` ;
            button.className = "border p-1 cursor-pointer position-absolute" ;
            button.style.top = "2px"
            button.style.right = "2px"
            button.addEventListener("click", async ()=>{
                await navigator.clipboard.writeText(codeStr);
            });

            codeEl.classList.add("position-relative") ;
            codeEl.classList.add("d-block") ;
            
            if(lang === "json"){
                lang = "javascript" ;
            }
            const codeDiv = document.createElement("DIV") ;
            codeDiv.style.backgroundColor = "#292D3E";
            codeDiv.style.padding = "5px 32px 5px 5px";
            codeDiv.innerHTML = await codeToHtml(codeStr, { lang: lang, theme: 'material-theme-palenight' })
            codeEl.innerHTML = "";
            codeEl.appendChild(button);
            codeEl.appendChild(codeDiv);            
        }
    }
}

view.displayed = async ()=>{

    view.data.addListener("permissions.roles.permissions.*", (ev)=>{
        view.updatePermission(ev.target) ;
    })

    const scrollSpy = new bootstrap.bootstrap.ScrollSpy(document.body, {
        target: '#navbar-users'
    }) ;

    const links = view.getElementById("navbar-users").querySelectorAll("a");
    for(let link of links){
        link.addEventListener("click", ev=>{
            ev.preventDefault();
            ev.stopPropagation() ;
            view.getElementById(link.getAttribute("href").replace("#", "")).scrollIntoView() ;
        }) ;
    }

    doHighlight();

}

view.updatePermission = async (permission)=>{
    if(permission.allowed){
        await dbApi.db.users.mutations.role_table_set_permissions({
            input: {
                permissions: permission.permission,
                role_name: permission.role,
                table_schema: permission.table_schema,
                table_name: permission.table_name
            }
        }) ;
    }else{
        await dbApi.db.users.mutations.role_table_remove_permissions({
            input: {
                permissions: permission.permission,
                role_name: permission.role,
                table_schema: permission.table_schema,
                table_name: permission.table_name
            }
        })
    }
};



view.saveSettings = async()=>{
    const settings = view.data.settings;

    await dbApi.db.users.settings.updateById(settings.id, settings) ;
}

view.deleteRole = async (role)=>{
    if(await dialogs.confirm("Are you sure to delete this role ?")){
        await dbApi.db.users.role.deleteByRole(role.role) ;
        view.data.roles = await dbApi.db.users.role.search({}, {orderBy: ['DISPLAY_ORDER_ASC']});
    }
};

view.addRole = async ()=>{
    let {modal, element} = dialogs.modal({
        title: "Create role",
        bodyContents: `<input type="text" class="form-control input-role" placeholder="Role name" />`,
        footerContents: `<button type="button" class="btn btn-primary button-create">Create</button>`
    }) ;
    let inputRoleName = element.querySelector(".input-role") ;
    element.addEventListener('shown.bs.modal', ()=>{
        inputRoleName.focus() ;
    })
    element.querySelector(".button-create").addEventListener("click", async ()=>{
        if(inputRoleName.value){
            modal.hide() ;
            waiter(async ()=>{
                await dbApi.db.users.role.create({role: inputRoleName.value});
                view.data.roles = await dbApi.db.users.role.search({}, {orderBy: ['DISPLAY_ORDER_ASC']});
            })
        }
    })
}

view.addAuthProvider = async ()=>{
    await dialogs.routeModal({ route: "/popup-auth-provider/" }) ;
    await view.refresh() ;
}

view.editAuthProvider = async (authProvider)=>{
    await dialogs.routeModal({ route: "/popup-auth-provider/"+authProvider.code }) ;
    await view.refresh() ;
}
view.deleteAuthProvider = async (authProvider)=>{
    if(await dialogs.confirm("Are you sure to delete this auth provider ?")){
        await dbApi.db.users.auth_providers.deleteByCode(authProvider.code)
        await view.refresh() ;
    }
}

view.addUser = async ()=>{
    await dialogs.routeModal({ route: "/popup-user/" }) ;
    await view.refresh() ;
}

view.editUser = async (user)=>{
    await dialogs.routeModal({ route: "/popup-user/"+user.login }) ;
    await view.refresh() ;
}
view.deleteUser = async (user)=>{
    if(await dialogs.confirm("Are you sure to delete this user ?")){
        await dbApi.db.users.user.deleteByLogin(user.login)
        await view.refresh() ;
    }
}

view.createUser = async function(){
    const createdUser = await usersApi.createUser({ login: view.data.create_login, email: view.data.create_email, password: view.data.create_password }) ;
    dialogs.info("User created "+JSON.stringify(createdUser)) ;
}

view.activateUser = async ()=>{
    const activated = await usersApi.activateUser(view.data.activation_token) ;
    if(activated){
        dialogs.info("Activation successful") ;
    }else{
        dialogs.error("Invalid token") ;
    }
    view.refresh() ;
}

view.requestResetPassword = async ()=>{
    const success = await usersApi.requestPasswordReset(view.data.reset_password_email) ;
    if(success){
        dialogs.info("Reset password request successful") ;
    }else{
        dialogs.error("User not found or not active") ;
    }
    view.refresh() ;
}

view.resetPassword = async ()=>{
    const success = await usersApi.resetPassword(view.data.reset_password_token, view.data.reset_password_password) ;
    if(success){
        dialogs.info("Reset password successful") ;
    }else{
        dialogs.error("Invalid token") ;
    }
    view.refresh() ;
}

view.authenticateUser = async function(){
    const authOk = await usersApi.authenticateUser(view.data.auth_login, view.data.auth_password) ;
    if(authOk){
        view.data.auth_error = null ;
        dialogs.info("Login successful") ;
    }else{
        view.data.auth_error = "Authentication of user failed. Check the login and password" ;
    }
}

view.logoutUser = async function(){
    await usersApi.logoutUser() ;
}
view.refreshToken = async function(){
    const succeed = await usersApi.refreshToken() ;
    if(succeed){
        dialogs.info("The token is refreshed")
    }else{
        dialogs.error("Impossible to refresh the token")
    }
}

view.changePassword = async function(){
    const succeed = await usersApi.changePassword(view.data.old_password, view.data.new_password) ;
    if(succeed){
        dialogs.info("The password has been changed")
    }else{
        dialogs.error("Wrong password")
    }
}


view.getCurrentUser = async function(){
    const currentUser = await usersApi.getCurrentUser() ;
    const currentUserStr = JSON.stringify(currentUser, null, 2) ;
    view.data.currentUserStr = currentUserStr;
    const resultEl = view.getElementById("current-user-result");
    resultEl.removeAttribute("code-rendered");
    resultEl.innerHTML = `<pre>${currentUserStr}</pre>`;
    doHighlight();
}

view.updateCurrentUser = async function(){
    const currentUser = await usersApi.updateCurrentUser({email: view.data.update_email}) ;
    const currentUserStr = JSON.stringify(currentUser, null, 2) ;
    view.data.updatedUserStr = currentUserStr;
    const resultEl = view.getElementById("updated-user-result");
    resultEl.removeAttribute("code-rendered");
    resultEl.innerHTML = `<pre>${currentUserStr}</pre>`;
    doHighlight();
}

view.policiesList = async ()=>{
    const policies = await dbApi.db.users.mutations.policies_list();
    const policiesStr = JSON.stringify(policies, null, 2) ;
    view.data.policiesStr = policiesStr;
    const resultEl = view.getElementById("policies-list-result");
    resultEl.removeAttribute("code-rendered");
    resultEl.innerHTML = `<pre>${policiesStr}</pre>`;
    doHighlight();
} ;

view.addPolicy = async ()=>{
    await dbApi.db.users.mutations.policy_add({
        input: {
            table_schema: view.data.policy_schema,
            table_name: view.data.policy_table,
            policy_name: view.data.policy_name,
            role_name: view.data.policy_role,
            condition: view.data.policy_condition,
        }
    }) ;
    view.refresh() ;
}

view.removePolicy = async (pol, p)=>{
    if(await dialogs.confirm("Are you sure to delete this policy ?")){
        await dbApi.db.users.mutations.policy_remove({
            input: {
                table_schema: p.table_schema,
                table_name: p.table_name,
                policy_name: pol.policy_name,
            }
        })
        view.refresh() ;
    }
}

view.policyEnable = async (p)=>{
    await dbApi.db.users.mutations.policy_enable({
        input: {
            table_schema: p.table_schema,
            table_name: p.table_name,
        }
    })
    view.refresh() ;
}

view.policyDisable = async (p)=>{
    await dbApi.db.users.mutations.policy_disable({
        input: {
            table_schema: p.table_schema,
            table_name: p.table_name,
        }
    })
    view.refresh() ;
}


view.getRoleTableListPermissions = async ()=>{
    const permissions = await dbApi.db.users.mutations.role_table_list_permissions();
    const listPermissionResult = JSON.stringify(permissions, null, 2) ;
    view.data.listPermissionResult = listPermissionResult;
    const resultEl = view.getElementById("list-permission-result");
    resultEl.removeAttribute("code-rendered");
    resultEl.innerHTML = `<pre>${listPermissionResult}</pre>`;
    doHighlight();
} ;




view.addPermission = async ()=>{
    await dbApi.db.users.mutations.role_table_set_permissions({
        input: {
            table_schema: view.data.permission_schema,
            table_name: view.data.permission_table,
            role_name: view.data.permission_role,
            permissions: view.data.permission_permission
        }
    }) ;
    view.refresh() ;
} ;
view.removePermission = async ()=>{
    await dbApi.db.users.mutations.role_table_remove_permissions({
        input: {
            table_schema: view.data.permission_schema,
            table_name: view.data.permission_table,
            role_name: view.data.permission_role,
            permissions: view.data.permission_permission
        }
    }) ;
    view.refresh() ;
} ;


view.testRead = async function(){
    try{
        let foos = await dbApi.db.foo.search()
        console.log(foos) ;
    }catch(err){
        console.log("err reading foo", err) ;
    }
    try{
        let anos = await dbApi.db.ano.search() ;
        console.log(anos) ;
    }catch(err){
        console.log("err reading anos", err) ;
    }
    try{
        let result = await dbApi.db.openbamz.plugins.search() ;
        console.log(result) ;
    }catch(err){
        console.log("err reading openbamz plugins", err) ;
    }
    try{
        let result = await dbApi.db.bootstrap5.variable.search() ;
        console.log(result) ;
    }catch(err){
        console.log("err reading bootstrap5 variable", err) ;
    }
    try{
        let result = await dbApi.db.users.user.search();
        console.log(result) ;
    }catch(err){
        console.log("err reading user variable", err) ;
    }
}

view.testInsert = async function(){
    try{
        let foos = await dbApi.db.foo.create({ name: "test" })
        console.log(foos) ;
    }catch(err){
        console.log("err insert in foo", err) ;
    }
    try{
        let anos = await dbApi.db.ano.create({ name: "test" }) ;
        console.log(anos) ;
    }catch(err){
        console.log("err insert in anos", err) ;
    }
    try{
        let result = await dbApi.db.openbamz.plugins.create({ plugin_id: "test" })
        console.log(result) ;
    }catch(err){
        console.log("err insert in openbamz plugins", err) ;
    }
    try{
        let result = await dbApi.db.bootstrap5.variable.create({ variable: "primary", value: "red"})
        console.log(result) ;
    }catch(err){
        console.log("err insert in bootstrap5 variable", err) ;
    }
    try{
        let result = await dbApi.db.users.user.create({login: "user"+new Date().getTime()})
        console.log(result) ;
    }catch(err){
        console.log("err insert in user", err) ;
    }
}

view.testUpdate = async function(){
    try{
        let foos = await dbApi.db.foo.updateBy_id("6438dec7-96d4-4320-8a2d-d64b2e38164f", {name: "test update"+new Date().getTime()})
        console.log(foos) ;
    }catch(err){
        console.log("err update in foo", err) ;
    }
    try{
        let anos = await dbApi.db.ano.updateBy_id("47c03e76-3f55-45b3-bda0-78abf3b56831", {name: "test update"+new Date().getTime()})
        console.log(anos) ;
    }catch(err){
        console.log("err update in anos", err) ;
    }
    
    try{
        let result = await dbApi.db.bootstrap5.variable.updateByVariable("primary",{ value: "blue"})
        console.log(result) ;
    }catch(err){
        console.log("err update in bootstrap5 variable", err) ;
    }
    try{
        let result = await dbApi.db.users.user.updateByLogin("test", {email: "test@test.com"})
        console.log(result) ;
    }catch(err){
        console.log("err update in user", err) ;
    }
}

view.testDelete = async function(){
    try{
        let foos = await dbApi.db.foo.deleteBy_id("6438dec7-96d4-4320-8a2d-d64b2e38164f")
        console.log(foos) ;
    }catch(err){
        console.log("err delete in foo", err) ;
    }
    try{
        let anos = await dbApi.db.ano.deleteBy_id("47c03e76-3f55-45b3-bda0-78abf3b56831")
        console.log(anos) ;
    }catch(err){
        console.log("err delete in anos", err) ;
    }
    try{
        let anos = await dbApi.db.openbamz.plugins.deleteByPlugin_id("test") ;
        console.log(anos) ;
    }catch(err){
        console.log("err delete in openbamz plugins", err) ;
    }
    
    try{
        let result = await dbApi.db.bootstrap5.variable.deleteByVariable("primary")
        console.log(result) ;
    }catch(err){
        console.log("err delete in bootstrap5 variable", err) ;
    }
}

view.refreshUser = async function(){
    try {
        let result = await dbApi.db.users.mutations.user_refresh({input:{}})
        let token = result;
        localStorage.setItem("openbamz-app-jwt", token) ;
    }catch(err){
        return false;
    }
}

view.login = async function(){
    let result = await dbApi.db.users.mutations.user_authenticate({input: {login: view.data.login, password: view.data.password}})
    let token = result;
    if(token){
        localStorage.setItem("openbamz-app-jwt", token) ;
        return true
    }else{
        return false;
    }
}

view.logout = async function(){
    localStorage.removeItem("openbamz-app-jwt") ;
    view.data.logged = false;
}