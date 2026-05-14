package com.substring.authapp.utils;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class PrivacyHelperTest {

    @Test
    void maskEmail_ShouldMaskCorrectly() {
        assertThat(PrivacyHelper.maskEmail("john.doe@example.com")).isEqualTo("j***e@example.com");
        assertThat(PrivacyHelper.maskEmail("ab@test.com")).isEqualTo("a***b@test.com");
        assertThat(PrivacyHelper.maskEmail("a@b.com")).isEqualTo("a***@b.com");
        assertThat(PrivacyHelper.maskEmail(null)).isNull();
        assertThat(PrivacyHelper.maskEmail("invalid-email")).isEqualTo("invalid-email");
    }
}
