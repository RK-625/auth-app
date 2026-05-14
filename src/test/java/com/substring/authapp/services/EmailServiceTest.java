package com.substring.authapp.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @InjectMocks
    private EmailService emailService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(emailService, "fromAddress", "noreply@example.com");
    }

    @Test
    void testSendSignUpOtp_Success() {
        String toAddress = "test@example.com";
        String otp = "123456";

        emailService.sendSignUpOtp(toAddress, otp);

        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getTo()[0]).isEqualTo(toAddress);
        assertThat(sentMessage.getFrom()).isEqualTo("noreply@example.com");
        assertThat(sentMessage.getSubject()).isEqualTo("Signup Verification");
        assertThat(sentMessage.getText()).contains(otp);
    }

    @Test
    void testSendPassWordResetOtp_Success() {
        String toAddress = "reset@example.com";
        String otp = "654321";

        emailService.sendPassWordResetOtp(toAddress, otp);

        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getTo()[0]).isEqualTo(toAddress);
        assertThat(sentMessage.getFrom()).isEqualTo("noreply@example.com");
        assertThat(sentMessage.getSubject()).isEqualTo("Password Reset Verification");
        assertThat(sentMessage.getText()).contains(otp);
    }

    @Test
    void testSendEmail_WhenMailException_ShouldCatchAndLog() {
        String toAddress = "error@example.com";
        String otp = "111111";

        org.mockito.Mockito.doThrow(new org.springframework.mail.MailSendException("SMTP server down"))
                .when(mailSender).send(org.mockito.ArgumentMatchers.any(SimpleMailMessage.class));

        // The method should catch the MailException and NOT throw it further,
        // ensuring background execution remains stable.
        assertThatCode(() -> emailService.sendSignUpOtp(toAddress, otp))
                .doesNotThrowAnyException();
        
        // Ensure that send was actually attempted
        verify(mailSender).send(org.mockito.ArgumentMatchers.any(SimpleMailMessage.class));
    }
}
