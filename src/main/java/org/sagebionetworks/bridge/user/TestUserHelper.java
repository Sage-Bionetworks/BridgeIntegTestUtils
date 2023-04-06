package org.sagebionetworks.bridge.user;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.sagebionetworks.bridge.util.IntegTestUtils.CONFIG;
import static org.sagebionetworks.bridge.util.IntegTestUtils.SAGE_ID;
import static org.sagebionetworks.bridge.util.IntegTestUtils.TEST_APP_ID;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.sagebionetworks.bridge.rest.ApiClientProvider;

import org.sagebionetworks.bridge.rest.ClientManager;
import org.sagebionetworks.bridge.rest.RestUtils;
import org.sagebionetworks.bridge.rest.api.AuthenticationApi;
import org.sagebionetworks.bridge.rest.api.ForAdminsApi;
import org.sagebionetworks.bridge.rest.exceptions.ConsentRequiredException;
import org.sagebionetworks.bridge.rest.model.ClientInfo;
import org.sagebionetworks.bridge.rest.model.Enrollment;
import org.sagebionetworks.bridge.rest.model.Environment;
import org.sagebionetworks.bridge.rest.model.Role;
import org.sagebionetworks.bridge.rest.model.SignIn;
import org.sagebionetworks.bridge.rest.model.SignUp;
import org.sagebionetworks.bridge.rest.model.UserSessionInfo;
import org.sagebionetworks.bridge.util.IntegTestUtils;

public class TestUserHelper {
    private static final Logger LOG = LoggerFactory.getLogger(TestUserHelper.class);

    private static final SignIn API_SIGN_IN = new SignIn().appId(TEST_APP_ID);
    private static final String ADMIN_EMAIL_PROPERTY = "synapse.test.user";
    private static final String ADMIN_PASSWORD_PROPERTY = "synapse.test.user.password";
    private static final SignIn ADMIN_SIGN_IN = new SignIn()
            .appId(TEST_APP_ID)
            .email(CONFIG.get(ADMIN_EMAIL_PROPERTY))
            .password(CONFIG.get(ADMIN_PASSWORD_PROPERTY));

    private static final List<String> LANGUAGES = Lists.newArrayList("en");
    private static final String PASSWORD = "P4ssword!";
    private static final ClientInfo CLIENT_INFO = new ClientInfo();
    static {
        CLIENT_INFO.setAppName("Integration Tests");
        CLIENT_INFO.setAppVersion(0);
    }
    
    private static BootstrapTestUser cachedAdmin;

    /** Static getter for ClientInfo, to let callers set the app name and version, possibly other parameters. */
    public static ClientInfo getClientInfo() {
        return CLIENT_INFO;
    }

    /**
     * Get the signed in, bootstrap admin user. This method will reset the administrator's app 
     * to be the API/test app, because this is a precondition expected by most of our tests and 
     * it's easy to break by failing to reset the admin users's app as part of test cleanup. Does
     * not force the reauthentication of the admin account. 
     */
    public static TestUser getSignedInAdmin() {
        return getSignedInAdmin(false);
    }
    /**
     * Same as getSignedInAdmin, but if forceSignIn is true, it will sign the admin in again. Some
     * tests that operate on OAuth actually end up signing out the admin user, so we must indicate
     * the account needs to be reauthenticated. 
     */
    public static TestUser getSignedInAdmin(boolean forceSignIn) {
        if (forceSignIn) {
            cachedAdmin = null;   
        }
        if (cachedAdmin == null) {
            try {
                ClientManager manager = createClientManager().withSignIn(ADMIN_SIGN_IN).build();
                AuthenticationApi authApi = manager.getClient(AuthenticationApi.class);
                UserSessionInfo session;
                if (CONFIG.getEnvironment() == Environment.PRODUCTION) {
                    session = RestUtils.signInWithSynapse(authApi, ADMIN_SIGN_IN);   
                } else {
                    session = RestUtils.signInWithSynapseDev(authApi, ADMIN_SIGN_IN);
                }
                cachedAdmin = new BootstrapTestUser(ADMIN_SIGN_IN, manager, session.getId());
            } catch(Exception e) {
                throw new RuntimeException(e);
            }
        }
        if (cachedAdmin.getAppId() != TEST_APP_ID) {
            try {
                cachedAdmin.getClient(AuthenticationApi.class).changeApp(API_SIGN_IN).execute();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return cachedAdmin;
    }

    // Returns the test user for the given sign-in credentials.
    public static TestUser getSignedInUser(SignIn signIn) {
        ClientManager manager = createClientManager().withSignIn(signIn).build();
        TestUser user = new TestUser(signIn, manager, null);
        user.signInAgain();
        return user;
    }
    
    private static ClientManager.Builder createClientManager() {
        return new ClientManager.Builder().withConfig(CONFIG).withClientInfo(CLIENT_INFO).withAcceptLanguage(LANGUAGES);
    }

    public static <T> T getNonAuthClient(Class<T> service, String appId) {
        ApiClientProvider provider = new ApiClientProvider(ClientManager.getUrl(CONFIG.getEnvironment()),
                RestUtils.getUserAgent(CLIENT_INFO), RestUtils.getAcceptLanguage(LANGUAGES), appId);

        return provider.getClient(service);
    }
    
    public static TestUser createAndSignInUser(Class<?> cls, String appId, Role... roles) throws IOException {
        TestUser admin = getSignedInAdmin();
        AuthenticationApi authApi = admin.getClient(AuthenticationApi.class);
        authApi.changeApp(new SignIn().appId(appId)).execute();
        TestUser createdUser = new TestUserHelper.Builder(cls).withAppId(appId).withRoles(roles).createAndSignInUser();
        authApi.changeApp(API_SIGN_IN).execute();
        return createdUser;
    }
    public static TestUser createAndSignInUser(Class<?> cls, boolean consentUser, Role... roles) throws IOException {
        return new TestUserHelper.Builder(cls).withRoles(roles).withConsentUser(consentUser).createAndSignInUser();
    }
    
    public static TestUser createAndSignInUser(Class<?> cls, boolean consentUser, SignUp signUp) throws IOException {
        return new TestUserHelper.Builder(cls).withConsentUser(consentUser).withSignUp(signUp).createAndSignInUser();
    }

    public static class Builder {
        private Class<?> cls;
        private String appId;
        private boolean consentUser;
        private boolean includeUserAgent = true;
        private SignUp signUp;
        private boolean setPassword = true;
        private ClientInfo clientInfo;
        private String externalId;
        private Map<String, String> externalIds;
        private Set<Role> roles = new HashSet<>();
        private String synapseUserId;
        private boolean testUser;
        private String userAgentOverride;

        public Builder withConsentUser(boolean consentUser) {
            this.consentUser = consentUser;
            return this;
        }

        /** True if you want the TestUser to include the User-Agent header in requests. Defaults to true. */
        public Builder withIncludeUserAgent(boolean includeUserAgent) {
            this.includeUserAgent = includeUserAgent;
            return this;
        }

        public Builder withSignUp(SignUp signUp) {
            this.signUp = signUp;
            return this;
        }
        public Builder withAppId(String appId) {
            this.appId = appId;
            return this;
        }
        public Builder withClientInfo(ClientInfo clientInfo) {
            this.clientInfo = clientInfo;
            return this;
        }
        public Builder withRoles(Role...roles) {
            Collections.addAll(this.roles, roles);
            return this;
        }
        public Builder withSetPassword(boolean setPassword) {
            this.setPassword = setPassword;
            return this;
        }
        public Builder withExternalId(String externalId) {
            this.externalId = externalId;
            return this;
        }
        public Builder withExternalIds(Map<String, String> externalIds) {
            this.externalIds = externalIds;
            return this;
        }
        public Builder withSynapseUserId(String synapseUserId) {
            this.synapseUserId = synapseUserId;
            return this;
        }
        public Builder withTestDataGroup() {
            this.testUser = true;
            return this;
        }

        /**
         * This is used to override the user agent string in the client manager. This is useful for
         * tests that need to test the user agent string.
         */
        public Builder withUserAgentOverride(String userAgentOverride) {
            this.userAgentOverride = userAgentOverride;
            return this;
        }

        public Builder(Class<?> cls) {
            checkNotNull(cls);
            this.cls = cls;
        }

        public TestUser createUser() throws IOException {
            if (clientInfo == null) {
                clientInfo = CLIENT_INFO;
            }
            TestUser admin = getSignedInAdmin();
            ForAdminsApi adminsApi = admin.getClient(ForAdminsApi.class);

            Set<Role> rolesList = new HashSet<>();
            if (signUp != null && signUp.getRoles() != null) {
                rolesList.addAll(signUp.getRoles());
            }
            if (!roles.isEmpty()) {
                rolesList.addAll(roles);
            }

            // For email address, we don't want consent emails to bounce or SES will get mad at us. All test user email
            // addresses should be in the form bridge-testing+[semi-unique token]@sagebase.org. This directs all test
            // email to bridge-testing@sagebase.org.
            String emailAddress = IntegTestUtils.makeEmail(cls);

            if (signUp == null) {
                signUp = new SignUp();
            }
            // If we haven't specified any identifier, provide an email address
            if (signUp.getEmail() == null && signUp.getPhone() == null && signUp.getExternalId() == null
                    && signUp.getExternalIds() == null) {
                signUp.email(emailAddress);
            }
            if (setPassword) {
                signUp.setPassword(PASSWORD);
            }
            if (appId != null) {
                signUp.setAppId(appId);
            }
            if (signUp.getAppId() == null){
                signUp.setAppId(admin.getAppId());
            }
            if (synapseUserId != null) {
                signUp.synapseUserId(synapseUserId);
            }
            signUp.setRoles(ImmutableList.copyOf(rolesList));
            signUp.setConsent(consentUser);
            if (testUser) {
                signUp.setDataGroups(ImmutableList.of("test_user"));    
            }
            if (externalId != null) {
                signUp.setExternalId(externalId);
            }
            UserSessionInfo info;
            try {
                info = adminsApi.createUser(signUp).execute().body();
                // Administrative accounts should be added to the Sage Bionetworks organization, which
                // has visibility into the two test studies.
                if (!signUp.getRoles().isEmpty()) {
                    adminsApi.addMember(SAGE_ID, info.getId()).execute();    
                }
                if (externalIds != null) {
                    for (Map.Entry<String,String> entry : externalIds.entrySet()) {
                        String studyId = entry.getKey();
                        String externalId = entry.getValue();
                        adminsApi.enrollParticipant(studyId, new Enrollment().userId(info.getId())
                                .externalId(externalId)).execute();
                    }
                }
            } catch (Exception ex) {
                LOG.error("Error creating account " + signUp + ": " + ex.getMessage());
                throw ex;
            }

            // Sign in should use email or phone if it exists, otherwise it uses external ID.
            SignIn signIn = new SignIn().appId(signUp.getAppId()).phone(signUp.getPhone())
                    .email(signUp.getEmail()).password(signUp.getPassword());
            if (signIn.getEmail() == null && signIn.getPhone() == null) {
                String finalExtId = signUp.getExternalId();
                if (signUp.getExternalIds() != null && !signUp.getExternalIds().isEmpty()) {
                    finalExtId = Iterables.getFirst(signUp.getExternalIds().values(), null);
                }
                signIn.externalId(finalExtId);
            }

            ClientManager manager = new ClientManager.Builder().withConfig(admin.getConfig()).withSignIn(signIn)
                    .withIncludeUserAgent(includeUserAgent).withClientInfo(clientInfo).withAcceptLanguage(LANGUAGES)
                    .withUserAgentOverride(userAgentOverride).build();
            return new TestUser(signIn, manager, info.getId());
        }

        public TestUser createAndSignInUser() throws IOException {
            TestUser testUser = createUser();

            try {
                testUser.signInAgain();
            } catch (ConsentRequiredException e) {
                if (consentUser) {
                    // If there's no consent but we're expecting one, that's an error.
                    throw e;
                }
            } catch (RuntimeException ex) {
                // Clean up the account, so we don't end up with a bunch of leftover accounts.
                if (testUser.getSession() != null) {
                    TestUser admin = getSignedInAdmin();
                    ForAdminsApi adminsApi = admin.getClient(ForAdminsApi.class);

                    adminsApi.deleteUser(testUser.getSession().getId()).execute();
                }
                throw ex;
            }
            return testUser;
        }
    }
}
