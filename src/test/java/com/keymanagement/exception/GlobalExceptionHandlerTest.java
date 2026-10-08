package com.keymanagement.exception;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.keymanagement.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();
    private final Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void setUp() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void testAllHandlers_ShouldSanitizeUrisAndMessagesWithoutChangingStatusCodes() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/keys/key\r\nFORGED");
        String message = "invalid\r\nFORGED\u2028entry";
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new FieldError("request", "username", message));
        MethodArgumentNotValidException validationException = mock(MethodArgumentNotValidException.class);
        when(validationException.getBindingResult()).thenReturn(bindingResult);

        List<ResponseEntity<ErrorResponse>> responses = List.of(
                handler.handleKeyNotFoundException(new KeyNotFoundException(message), request),
                handler.handleDecryptionException(new DecryptionException(message), request),
                handler.handleEncryptionException(new EncryptionException(message), request),
                handler.handleValidationException(validationException, request),
                handler.handleIllegalArgumentException(new IllegalArgumentException(message), request),
                handler.handleBadCredentialsException(new BadCredentialsException(message), request),
                handler.handleUsernameNotFoundException(new UsernameNotFoundException(message), request),
                handler.handleGenericException(new IllegalStateException(message), request)
        );

        assertEquals(List.of(HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST, HttpStatus.INTERNAL_SERVER_ERROR,
                HttpStatus.BAD_REQUEST, HttpStatus.BAD_REQUEST, HttpStatus.UNAUTHORIZED,
                HttpStatus.NOT_FOUND, HttpStatus.INTERNAL_SERVER_ERROR),
                responses.stream().map(ResponseEntity::getStatusCode).toList());
        assertEquals(8, appender.list.size());
        for (ILoggingEvent event : appender.list) {
            assertFalse(Pattern.compile("\\R").matcher(event.getFormattedMessage()).find(), event.getFormattedMessage());
            assertTrue(event.getFormattedMessage().contains("/api/keys/key_FORGED"));
            assertTrue(event.getFormattedMessage().contains("invalid_FORGED_entry"));
            assertNull(event.getThrowableProxy());
        }
    }

    @Test
    void testGenericHandler_ShouldKeepSanitizedCauseAndSuppressedExceptionDetails() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/keys");
        IllegalStateException exception = new IllegalStateException("outer\r\nFORGED",
                new IllegalArgumentException("cause\r\nFORGED"));
        exception.addSuppressed(new RuntimeException("suppressed\r\nFORGED"));

        handler.handleGenericException(exception, request);

        ILoggingEvent event = appender.list.getFirst();
        String loggedMessage = event.getFormattedMessage();
        assertFalse(Pattern.compile("\\R").matcher(loggedMessage).find(), loggedMessage);
        assertTrue(loggedMessage.contains("IllegalStateException: outer_FORGED"));
        assertTrue(loggedMessage.contains("IllegalArgumentException: cause_FORGED"));
        assertTrue(loggedMessage.contains("RuntimeException: suppressed_FORGED"));
        assertTrue(loggedMessage.contains("GlobalExceptionHandlerTest"));
        assertNull(event.getThrowableProxy());
    }
}