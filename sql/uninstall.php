<?php
/**
 * 2012-2026 SJBDIXITAL
 *
 * Eliminación de tablas del módulo sjbantibot.
 *
 * @author    Daniel "Cancrexo" Prol <cancrexo@gmail.com>
 * @copyright SJB Dixital
 * @license   Commercial License. All rights reserved
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

$sql = [];
$sql[] = 'DROP TABLE IF EXISTS `' . _DB_PREFIX_ . 'sjbantibot_attempt`';

foreach ($sql as $query) {
    if (!Db::getInstance()->execute($query)) {
        return false;
    }
}

return true;
