package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Prueba unitaria pura: el orden de las llamadas es lo que protege contra el
 * oraculo.
 */
class PasswordRecoveryServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000003");

    private CredentialService credentialService;
    private OtpService otpService;
    private PasswordPolicyService policy;
    private PasswordRecoveryService service;

    @BeforeEach
    void preparar() {
        credentialService = mock(CredentialService.class);
        otpService = mock(OtpService.class);
        policy = mock(PasswordPolicyService.class);
        service = new PasswordRecoveryService(credentialService, otpService, policy);
    }

    @Test
    void unaClaveDebilNoConsumeElOtpNiToca​LaCuenta() {
        doThrow(new WeakPasswordException("debil")).when(policy).validate(anyString());

        assertThrows(WeakPasswordException.class, () -> service.reset(USER_ID, "123456", "x"));

        verify(otpService, never()).verifyAndConsume(any(), anyString());
        verify(credentialService, never()).resetPassword(any(), anyString());
    }

    @Test
    void unOtpInvalidoNuncaComparaConLaClaveActual() {
        doThrow(new InvalidOtpException()).when(otpService).verifyAndConsume(USER_ID, "000000");

        assertThrows(InvalidOtpException.class,
                () -> service.reset(USER_ID, "000000", "Nueva#Clave2027"));

        verify(credentialService, never()).validateNewPassword(any(), anyString());
        verify(credentialService, never()).resetPassword(any(), anyString());
    }

    @Test
    void elOrdenEsPoliticaLuegoOtpLuegoCambio() {
        service.reset(USER_ID, "123456", "Nueva#Clave2027");

        InOrder orden = inOrder(policy, otpService, credentialService);
        orden.verify(policy).validate("Nueva#Clave2027");
        orden.verify(otpService).verifyAndConsume(USER_ID, "123456");
        orden.verify(credentialService).resetPassword(USER_ID, "Nueva#Clave2027");
    }
}