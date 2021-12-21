package org.sagebionetworks.bridge.user;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.util.List;

import org.sagebionetworks.bridge.rest.ClientManager;
import org.sagebionetworks.bridge.rest.Config;
import org.sagebionetworks.bridge.rest.model.Phone;
import org.sagebionetworks.bridge.rest.model.Role;
import org.sagebionetworks.bridge.rest.model.SignIn;
import org.sagebionetworks.bridge.rest.model.UserSessionInfo;

class BootstrapTestUser implements TestUser {
    
    private SignIn signIn;
    private ClientManager manager;
    private String userId; // try and hold onto this for the sake of cleaning up tests

    public BootstrapTestUser(SignIn signIn, ClientManager manager, String userId) {
        checkNotNull(signIn.getAppId());
        this.signIn = signIn;
        this.manager = checkNotNull(manager);
        this.userId = userId; // if this is null, we will try and get it on a sign in
    }
    public UserSessionInfo getSession() {
        return manager.getSessionOfClients();
    }
    public String getEmail() {
        return signIn.getEmail();
    }
    public Phone getPhone() {
        return signIn.getPhone();
    }
    public String getPassword() {
        return signIn.getPassword();
    }
    public List<Role> getRoles() {
        return (getSession() == null) ? null : getSession().getRoles();
    }
    public String getDefaultSubpopulation() {
        return signIn.getAppId();
    }
    public String getAppId() {
        return signIn.getAppId();
    }
    public String getUserId() {
        return userId;
    }
    public <T> T getClient(Class<T> service) {
        return manager.getClient(service);
    }
    public UserSessionInfo signInAgain() {
        throw new UnsupportedOperationException("You cannot sign in the boostrap admin again");
    }
    public void signOut() {
        throw new UnsupportedOperationException("You cannot sign out the boostrap admin");
    }
    public void signOutAndDeleteUser() {
        throw new UnsupportedOperationException("You cannot delete the boostrap admin");
    }
    public SignIn getSignIn() {
        return signIn;
    }
    public ClientManager getClientManager() {
        return manager;
    }
    public Config getConfig() {
        return manager.getConfig();
    }
}
