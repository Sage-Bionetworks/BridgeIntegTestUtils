package org.sagebionetworks.bridge.util;

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;

import org.apache.commons.lang3.RandomStringUtils;
import org.sagebionetworks.bridge.rest.Config;
import org.sagebionetworks.bridge.rest.api.ForAdminsApi;
import org.sagebionetworks.bridge.rest.api.ParticipantsApi;
import org.sagebionetworks.bridge.rest.model.AccountSummaryList;
import org.sagebionetworks.bridge.rest.model.Phone;
import org.sagebionetworks.bridge.rest.model.Role;
import org.sagebionetworks.bridge.user.TestUserHelper;

public class IntegTestUtils {
    public static final Config CONFIG = new Config();
    public static final Phone PHONE = new Phone().number("+19712486796").regionCode("US");
    public static final String STUDY_ID = "api";

    public static void deletePhoneUser(TestUserHelper.TestUser researcher) throws IOException {
        checkArgument(researcher.getRoles().contains(Role.RESEARCHER));

        ParticipantsApi participantsApi = researcher.getClient(ParticipantsApi.class);
        AccountSummaryList list = participantsApi.getParticipants(0, 5, null,
                IntegTestUtils.PHONE.getNumber(), null, null).execute().body();
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
