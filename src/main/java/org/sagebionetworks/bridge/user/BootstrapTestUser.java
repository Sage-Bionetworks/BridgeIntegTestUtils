package org.sagebionetworks.bridge.user;

import org.sagebionetworks.bridge.rest.ClientManager;
import org.sagebionetworks.bridge.rest.model.SignIn;
import org.sagebionetworks.bridge.rest.model.UserSessionInfo;

class BootstrapTestUser extends TestUser {
    
    public BootstrapTestUser(SignIn signIn, ClientManager manager, String userId) {
        super(signIn, manager, userId);
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
}
