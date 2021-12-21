package org.sagebionetworks.bridge.user;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.sagebionetworks.bridge.util.IntegTestUtils.TEST_APP_ID;

import java.io.IOException;
import java.util.List;

import org.sagebionetworks.bridge.rest.ClientManager;
import org.sagebionetworks.bridge.rest.Config;
import org.sagebionetworks.bridge.rest.api.AuthenticationApi;
import org.sagebionetworks.bridge.rest.api.ForAdminsApi;
import org.sagebionetworks.bridge.rest.exceptions.BadRequestException;
import org.sagebionetworks.bridge.rest.exceptions.BridgeSDKException;
import org.sagebionetworks.bridge.rest.model.Phone;
import org.sagebionetworks.bridge.rest.model.Role;
import org.sagebionetworks.bridge.rest.model.SignIn;
import org.sagebionetworks.bridge.rest.model.UserSessionInfo;

class TestUserImpl implements TestUser {
    
    private static final SignIn API_SIGN_IN = new SignIn().appId(TEST_APP_ID);
    
    private SignIn signIn;
    private ClientManager manager;
    private String userId; // try and hold onto this for the sake of cleaning up tests

    public TestUserImpl(SignIn signIn, ClientManager manager, String userId) {
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
        AuthenticationApi authApi = manager.getClient(AuthenticationApi.class);
        try {
            UserSessionInfo session = authApi.signInV4(getSignIn()).execute().body();
            userId = session.getId();
            return manager.getSessionOfClients();
        } catch(IOException ioe) {
            throw new BridgeSDKException(ioe.getMessage(), ioe);
        }
    }
    public void signOut() {
        try {
            AuthenticationApi authApi = manager.getClient(AuthenticationApi.class);
            authApi.signOut().execute();
        } catch(IOException ioe) {
            throw new BridgeSDKException(ioe.getMessage(), ioe);
        }
    }
    public void signOutAndDeleteUser() {
        if (getSession() != null) {
            try {
                this.signOut();
            } catch(BadRequestException e) {
                // It's possible at the end of some tests, the user isn't signed in.
            }
        }
        if (userId != null) {
            try {
                TestUser admin = TestUserHelper.getSignedInAdmin();
                boolean adminInWrongApp = !getAppId().equals(admin.getAppId());
                // If admin is in a different app, switch to the user's app before deletion.
                AuthenticationApi authApi = admin.getClient(AuthenticationApi.class);
                if (adminInWrongApp) {
                    authApi.changeApp(new SignIn().appId(getAppId())).execute();
                }
                ForAdminsApi adminsApi = admin.getClient(ForAdminsApi.class);
                adminsApi.deleteUser(userId).execute();
                // then switch back
                if (adminInWrongApp) {
                    authApi.changeApp(API_SIGN_IN).execute();
                }
            } catch(IOException ioe) {
                throw new BridgeSDKException(ioe.getMessage(), ioe);
            }
        }
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
