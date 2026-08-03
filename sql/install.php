<?php
/**
 * 2012-2026 SJBDIXITAL
 *
 * Creación de tablas del módulo sjbantibot.
 *
 * @author    Daniel "Cancrexo" Prol <cancrexo@gmail.com>
 * @copyright SJB Dixital
 * @license   Commercial License. All rights reserved
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

$sql = [];

$sql[] = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'sjbantibot_attempt` (
    `id_attempt` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip` VARCHAR(45) NOT NULL,
    `email_hash` CHAR(64) DEFAULT NULL,
    `created_at` DATETIME NOT NULL,
    `blocked` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
    `reason` VARCHAR(16) NOT NULL DEFAULT \'ok\',
    PRIMARY KEY (`id_attempt`),
    KEY `idx_ip_created` (`ip`, `created_at`),
    KEY `idx_reason_created` (`reason`, `created_at`)
) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8mb4;';

foreach ($sql as $query) {
    if (!Db::getInstance()->execute($query)) {
        return false;
    }
}

return true;
