package org.sagebionetworks.bridge.util;

import static com.google.common.base.Preconditions.checkArgument;
import static org.sagebionetworks.bridge.rest.model.Role.RESEARCHER;

import java.io.IOException;

import org.apache.commons.lang3.RandomStringUtils;
import org.sagebionetworks.bridge.rest.Config;
import org.sagebionetworks.bridge.rest.api.ForAdminsApi;
import org.sagebionetworks.bridge.rest.api.ParticipantsApi;
import org.sagebionetworks.bridge.rest.model.AccountSummaryList;
import org.sagebionetworks.bridge.rest.model.AccountSummarySearch;
import org.sagebionetworks.bridge.rest.model.Phone;
import org.sagebionetworks.bridge.user.TestUserHelper;

public class IntegTestUtils {
    public static final Config CONFIG = new Config();
    public static final Phone PHONE = new Phone().number("+19712486796").regionCode("US");
    public static final String TEST_APP_ID = "api";
    public static final String SHARED_APP_ID = "shared";
    public static final String SAGE_ID = "sage-bionetworks";

    public static void deletePhoneUser(TestUserHelper.TestUser researcher) throws IOException {
        checkArgument(researcher.getRoles().contains(RESEARCHER));

        ParticipantsApi participantsApi = researcher.getClient(ParticipantsApi.class);
        AccountSummarySearch search = new AccountSummarySearch().pageSize(5)
                .phoneFilter(PHONE.getNumber());
        AccountSummaryList list = participantsApi.searchAccountSummaries(search).execute().body();
        if (!list.getItems().isEmpty()) {
            TestUserHelper.TestUser admin = TestUserHelper.getSignedInAdmin();
            ForAdminsApi adminsApi = admin.getClient(ForAdminsApi.class);
            adminsApi.deleteUser(list.getItems().get(0).getId()).execute();
        }
    }

    public static String makeEmail(Class<?> cls) {
        String devName = CONFIG.getDevName();
        String clsPart = cls.getSimpleName();
        String rndPart = RandomStringUtils.randomAlphabetic(4);
        return String.format("bridge-testing+%s-%s-%s@sagebase.org", devName, clsPart, rndPart);
    }
}
