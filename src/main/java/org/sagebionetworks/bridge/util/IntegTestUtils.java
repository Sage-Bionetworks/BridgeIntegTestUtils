package org.sagebionetworks.bridge.util;

import org.apache.commons.lang3.RandomStringUtils;

import org.sagebionetworks.bridge.rest.Config;
import org.sagebionetworks.bridge.rest.model.Phone;

public class IntegTestUtils {
    public static final Config CONFIG = new Config();
    public static final Phone PHONE = new Phone().number("+19712486796").regionCode("US");
    public static final String STUDY_ID = "api";

    public static String makeEmail(Class<?> cls) {
        String devName = CONFIG.getDevName();
        String clsPart = cls.getSimpleName();
        String rndPart = RandomStringUtils.randomAlphabetic(4);
        return String.format("bridge-testing+%s-%s-%s@sagebase.org", devName, clsPart, rndPart);
    }
}
