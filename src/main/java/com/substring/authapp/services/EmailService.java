package com.substring.authapp.services;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {


    //rk625java
    //Java$123

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromAddress;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }


    public void sendPassWordResetOtp(String toAddress, String otp){
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setTo(toAddress);
        simpleMailMessage.setFrom(fromAddress);
        simpleMailMessage.setSubject("Password Reset OTP");
        simpleMailMessage.setText("Your verification code is: " + otp +
                                                  "\n\nThis code will expire in 1 minute.\n" +
                                                  "Please do not share it with anyone. Thank you!");
        mailSender.send(simpleMailMessage);
    }

}
