package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Restablece la contraseña tras verificar un OTP.
 * Orden deliberado:
 * 1) Politica de complejidad (no depende de la cuenta): evita consumir el
 * codigo con una clave debil.
 * 2) OTP: sin un codigo valido no se revela nada mas sobre la cuenta.
 * 3) Cambio: aqui se compara con la clave actual. Si falla, la transaccion se
 * revierte
 * y el OTP no queda consumido. Un OTP incorrecto si conserva su intento
 * (noRollbackFor).
 */
@Service
public class PasswordRecoveryService {

    private final CredentialService credentialService;
    private final OtpService otpService;
    private final PasswordPolicyService passwordPolicy;

    public PasswordRecoveryService(CredentialService credentialService,
            OtpService otpService,
            PasswordPolicyService passwordPolicy) {
        this.credentialService = credentialService;
        this.otpService = otpService;
        this.passwordPolicy = passwordPolicy;
    }

    @Transactional(noRollbackFor = InvalidOtpException.class)
    public void reset(UUID userId, String code, String newPassword) {
        passwordPolicy.validate(newPassword);
        otpService.verifyAndConsume(userId, code);
        credentialService.resetPassword(userId, newPassword);
    }
}