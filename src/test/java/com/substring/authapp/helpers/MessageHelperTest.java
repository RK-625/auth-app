package com.substring.authapp.helpers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("MessageHelper Unit Tests")
class MessageHelperTest {

    @Mock
    private MessageSource messageSource;

    @InjectMocks
    private MessageHelper messageHelper;

    @Test
    @DisplayName("Should return localized message from source")
    void getMessage_ShouldReturnLocalizedMessage() {
        String key = "test.key";
        String expectedMessage = "Localized Message";
        Locale locale = LocaleContextHolder.getLocale();

        when(messageSource.getMessage(eq(key), any(), eq(locale))).thenReturn(expectedMessage);

        String actualMessage = messageHelper.getMessage(key);

        assertThat(actualMessage).isEqualTo(expectedMessage);
    }

    @Test
    @DisplayName("Should return formatted localized message with arguments")
    void getMessage_WithArgs_ShouldReturnFormattedMessage() {
        String key = "test.key.args";
        Object[] args = new Object[]{"Arg1", 123};
        String expectedMessage = "Message with Arg1 and 123";
        Locale locale = LocaleContextHolder.getLocale();

        when(messageSource.getMessage(eq(key), eq(args), eq(locale))).thenReturn(expectedMessage);

        String actualMessage = messageHelper.getMessage(key, args);

        assertThat(actualMessage).isEqualTo(expectedMessage);
    }
}
