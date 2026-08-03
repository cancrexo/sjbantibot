<?php
/**
 * 2012-2026 SJBDIXITAL
 *
 * Helper de protección local: timing HMAC, rate limit e intentos en BBDD.
 * Política: se registran solo intentos FALLIDOS (honeypot|timing|rate).
 * Al alcanzar max intentos en la ventana, se inserta reason=rate y se bloquea
 * la IP durante block_minutes.
 *
 * @author    Daniel "Cancrexo" Prol <cancrexo@gmail.com>
 * @copyright SJB Dixital
 * @license   Commercial License. All rights reserved
 */
declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

class SjbAntibotGuard
{
    const TABLE = 'sjbantibot_attempt';
    const SESSION_TS_KEY = 'sjbantibot_form_ts';
    const REASON_HONEYPOT = 'honeypot';
    const REASON_TIMING = 'timing';
    const REASON_RATE = 'rate';
    const REASON_OK = 'ok';
    const CLEANUP_HOURS = 48;

    /** @var array */
    protected $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Genera token HMAC local (timestamp.firma) y guarda el timestamp en sesión.
     */
    public function issueTimingToken(): string
    {
        $ts = time();
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $_SESSION[self::SESSION_TS_KEY] = $ts;

        return $ts . '.' . $this->signTimestamp($ts);
    }

    /**
     * Valida token HMAC + sesión y comprueba el tiempo mínimo.
     * Devuelve null si OK, o el reason si falla.
     */
    public function checkTiming(?string $token): ?string
    {
        $minSeconds = (int) ($this->config['timing_min'] ?? 4);
        $now = time();
        $ts = null;

        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }

        // Preferir sesión (no falsificable desde el cliente)
        if (!empty($_SESSION[self::SESSION_TS_KEY])) {
            $ts = (int) $_SESSION[self::SESSION_TS_KEY];
        }

        // Validar también el token HMAC del hidden
        if ($token === null || $token === '' || strpos($token, '.') === false) {
            return self::REASON_TIMING;
        }

        list($tokenTs, $sig) = explode('.', $token, 2);
        $tokenTs = (int) $tokenTs;

        if ($tokenTs <= 0 || !hash_equals($this->signTimestamp($tokenTs), (string) $sig)) {
            return self::REASON_TIMING;
        }

        // Si hay sesión, debe coincidir con el token (anti-replay básico)
        if ($ts !== null && $ts !== $tokenTs) {
            // Aceptamos el menor (más antiguo) si ambos son válidos y recientes
            $ts = min($ts, $tokenTs);
        } else {
            $ts = $tokenTs;
        }

        if (($now - $ts) < $minSeconds) {
            return self::REASON_TIMING;
        }

        // Token usado: limpiar sesión para limitar reutilización
        unset($_SESSION[self::SESSION_TS_KEY]);

        return null;
    }

    protected function signTimestamp(int $ts): string
    {
        $payload = (string) $ts . '|' . (string) session_id();
        $key = defined('_COOKIE_KEY_') ? (string) _COOKIE_KEY_ : (string) _DB_PASSWD_;

        return hash_hmac('sha256', $payload, $key);
    }

    public function getClientIp(): string
    {
        return (string) Tools::getRemoteAddr();
    }

    public function hashEmail(?string $email): ?string
    {
        $email = trim((string) $email);
        if ($email === '') {
            return null;
        }

        return hash('sha256', Tools::strtolower($email));
    }

    /**
     * ¿IP bloqueada por superar el rate limit?
     * Bloqueo activo si existe un reason=rate en los últimos block_minutes.
     */
    public function isIpBlocked(string $ip): bool
    {
        $blockMinutes = (int) ($this->config['block_minutes'] ?? 30);
        $sql = 'SELECT 1 FROM `' . _DB_PREFIX_ . self::TABLE . '`
            WHERE `ip` = "' . pSQL($ip) . '"
              AND `reason` = "' . pSQL(self::REASON_RATE) . '"
              AND `created_at` >= DATE_SUB(NOW(), INTERVAL ' . (int) $blockMinutes . ' MINUTE)
            LIMIT 1';

        return (bool) Db::getInstance()->getValue($sql);
    }

    /**
     * Cuenta fallos (honeypot|timing|rate) en la ventana configurada.
     */
    public function countFailuresInWindow(string $ip): int
    {
        $window = (int) ($this->config['window_minutes'] ?? 15);
        $sql = 'SELECT COUNT(*) FROM `' . _DB_PREFIX_ . self::TABLE . '`
            WHERE `ip` = "' . pSQL($ip) . '"
              AND `reason` IN ("' . pSQL(self::REASON_HONEYPOT) . '","' . pSQL(self::REASON_TIMING) . '","' . pSQL(self::REASON_RATE) . '")
              AND `created_at` >= DATE_SUB(NOW(), INTERVAL ' . (int) $window . ' MINUTE)';

        return (int) Db::getInstance()->getValue($sql);
    }

    /**
     * Registra un intento fallido. Si se alcanza el umbral, marca también rate.
     */
    public function recordFailure(string $ip, string $reason, ?string $emailHash = null): void
    {
        $this->insertAttempt($ip, $reason, $emailHash, true);

        $max = (int) ($this->config['max_attempts'] ?? 5);
        if ($reason !== self::REASON_RATE && $this->countFailuresInWindow($ip) >= $max) {
            $this->insertAttempt($ip, self::REASON_RATE, $emailHash, true);
        }
    }

    protected function insertAttempt(string $ip, string $reason, ?string $emailHash, bool $blocked): void
    {
        $row = [
            'ip' => pSQL($ip),
            'created_at' => date('Y-m-d H:i:s'),
            'blocked' => $blocked ? 1 : 0,
            'reason' => pSQL($reason),
        ];
        if ($emailHash) {
            $row['email_hash'] = pSQL($emailHash);
        }

        Db::getInstance()->insert(self::TABLE, $row);
    }

    /**
     * Limpieza oportunista de filas antiguas (> 48 h).
     */
    public function cleanupOldRows(): void
    {
        Db::getInstance()->execute(
            'DELETE FROM `' . _DB_PREFIX_ . self::TABLE . '`
             WHERE `created_at` < DATE_SUB(NOW(), INTERVAL ' . (int) self::CLEANUP_HOURS . ' HOUR)'
        );
    }
}
