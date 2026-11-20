package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.repository.OtpRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sin @Transactional a proposito: se prueban las fronteras reales de
 * transaccion.
 * Solo datos ficticios.
 */
@SpringBootTest
@ActiveProfiles("test")
class PasswordRecoveryIntegrationTest {

    private static final UUID USER_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final String CLAVE_ACTUAL = "Segura#Clave2026";
    private static final String CLAVE_NUEVA = "Nueva#Clave2027";
    private static final String CODIGO_FALSO = "no-es-el-codigo";

    @Autowired
    private PasswordRecoveryService recovery;
    @Autowired
    private CredentialService credentialService;
    @Autowired
    private OtpService otpService;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private OtpRepository otpRepository;
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private Clock clock;

    @BeforeEach
    @AfterEach
    void limpiar() {
        otpRepository.deleteAll();
        credentialRepository.deleteAll();
    }

    private Optional<Otp> otpVigente() {
        return otpRepository.findActive(USER_ID, OtpPurpose.RESET_PASSWORD, LocalDateTime.now(clock));
    }

    @Test
    void conCodigoFalsoNuncaSeRevelaSiLaClaveEsLaActual() {
        credentialService.create(USER_ID, "usuario.prueba@example.com", CLAVE_ACTUAL);
        otpService.generate(USER_ID);

        // Antes del arreglo esto lanzaba WeakPasswordException ("diferente a la
        // actual"): el oraculo.
        assertThrows(InvalidOtpException.class,
                () -> recovery.reset(USER_ID, CODIGO_FALSO, CLAVE_ACTUAL));
    }

    @Test
    void claveIgualALaActualConOtpValidoSeRechazaYNoConsumeElOtp() {
        credentialService.create(USER_ID, "usuario.prueba@example.com", CLAVE_ACTUAL);
        String codigo = otpService.generate(USER_ID);

        assertThrows(WeakPasswordException.class,
                () -> recovery.reset(USER_ID, codigo, CLAVE_ACTUAL));

        assertTrue(otpVigente().isPresent(), "el OTP debe seguir vigente tras el rechazo");
    }

    @Test
    void codigoFalsoSumaUnIntentoYSePersiste() {
        credentialService.create(USER_ID, "usuario.prueba@example.com", CLAVE_ACTUAL);
        otpService.generate(USER_ID);

        assertThrows(InvalidOtpException.class,
                () -> recovery.reset(USER_ID, CODIGO_FALSO, CLAVE_NUEVA));

        assertEquals(1, otpVigente().orElseThrow().getAttempts());
    }

    @Test
    void resetExitosoCambiaLaClaveYConsumeElOtp() {
        credentialService.create(USER_ID, "usuario.prueba@example.com", CLAVE_ACTUAL);
        String codigo = otpService.generate(USER_ID);

        recovery.reset(USER_ID, codigo, CLAVE_NUEVA);

        String hash = credentialRepository.findByUserId(USER_ID).orElseThrow().getPasswordHash();
        assertTrue(encoder.matches(CLAVE_NUEVA, hash));
        assertFalse(otpVigente().isPresent());
    }
}