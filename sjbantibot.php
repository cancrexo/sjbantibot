<?php
/**
 * 2012-2026 SJBDIXITAL
 *
 * Módulo de protección anti-bots LOCAL para el registro de clientes.
 * Técnicas: honeypot + timing (HMAC local) + rate limit por IP.
 * Sin proveedores externos ni reCAPTCHA/Turnstile.
 *
 * @author    Daniel "Cancrexo" Prol <cancrexo@gmail.com>
 * @copyright SJB Dixital
 * @license   Commercial License. All rights reserved
 */
declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once dirname(__FILE__) . '/classes/SjbAntibotGuard.php';

class sjbantibot extends Module
{
    const PREFIX = 'SJBANTIBOT_';

    /** Nombre inocente del campo honeypot (no "honeypot") */
    const HP_FIELD = 'company_url';

    /** Campo hidden con token de timing firmado */
    const TS_FIELD = 'reg_token';

    protected $_hooks = [
        'additionalCustomerFormFields',
        'validateCustomerFormFields',
        'actionFrontControllerSetMedia',
    ];

    /**
     * Config: clave => [valor por defecto]
     */
    protected $default_config = [
        'enabled' => [1],
        'timing_min' => [4],
        'max_attempts' => [5],
        'window_minutes' => [15],
        'block_minutes' => [30],
        'debug_enabled' => [0],
        'remove_data' => [1],
    ];

    /** @var bool */
    public static $debugEnabled = false;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->name = 'sjbantibot';
        $this->tab = 'front_office_features';
        $this->version = '1.0.0';
        $this->need_instance = 0;
        $this->author = 'Daniel "Cancrexo" Prol';
        $this->ps_versions_compliancy = ['min' => '1.7.6', 'max' => _PS_VERSION_];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('SJB AntiBot (registro)');
        $this->description = $this->l('Protección local anti-bots en el registro de clientes: honeypot, timing y rate limit.');
        $this->confirmUninstall = $this->l('¿Seguro que quieres desinstalar este módulo?');

        static::$debugEnabled = (bool) Configuration::get(self::PREFIX . 'DEBUG_ENABLED');
    }

    /**
     * Log vía PrestaShopLogger solo si el debug está activo.
     */
    public static function debug($msg = '', $level = 1)
    {
        if (!static::$debugEnabled) {
            return;
        }
        PrestaShopLogger::addLog('[sjbantibot] ' . $msg, (int) $level);
    }

    public function install()
    {
        if (!parent::install()) {
            return false;
        }

        if (!$this->installDb()) {
            return false;
        }

        foreach ($this->_hooks as $hook) {
            if (!$this->registerHook($hook)) {
                static::debug('Error registrando hook ' . $hook, 3);

                return false;
            }
        }

        return (bool) $this->defaultValues();
    }

    public function uninstall()
    {
        $removeData = (bool) Configuration::get(self::PREFIX . 'REMOVE_DATA');

        if ($removeData) {
            $this->uninstallDb();
            foreach (array_keys($this->default_config) as $key) {
                Configuration::deleteByName(self::PREFIX . Tools::strtoupper($key));
            }
        }

        return parent::uninstall();
    }

    protected function installDb()
    {
        return (bool) include dirname(__FILE__) . '/sql/install.php';
    }

    protected function uninstallDb()
    {
        return (bool) include dirname(__FILE__) . '/sql/uninstall.php';
    }

    /**
     * Valores por defecto en Configuration.
     */
    protected function defaultValues()
    {
        foreach ($this->default_config as $key => $value) {
            $cfgKey = self::PREFIX . Tools::strtoupper($key);
            if (!Configuration::hasKey($cfgKey)) {
                Configuration::updateValue($cfgKey, reset($value));
            }
        }

        return true;
    }

    /**
     * Lee la config activa del módulo.
     */
    protected function getConfig(): array
    {
        $cfg = [];
        foreach ($this->default_config as $key => $value) {
            $stored = Configuration::get(self::PREFIX . Tools::strtoupper($key));
            $cfg[$key] = ($stored === false || $stored === null) ? reset($value) : $stored;
        }

        return $cfg;
    }

    /**
     * ¿Aplicar protección en esta página?
     * Solo registro (auth/registration) y checkout (order). No identity ni contacto.
     */
    protected function isProtectedPage(): bool
    {
        $controller = isset($this->context->controller->php_self)
            ? (string) $this->context->controller->php_self
            : '';

        $allowed = ['authentication', 'registration', 'order', 'checkout'];

        return in_array($controller, $allowed, true);
    }

    protected function getGenericErrorMessage(): string
    {
        return $this->l('No se pudo crear la cuenta. Inténtalo de nuevo.');
    }

    /*
     * -------------------------------------------------------------------------
     * HOOKS FRONT
     * -------------------------------------------------------------------------
     */

    /**
     * Inyecta honeypot (text) + token de timing (hidden).
     *
     * @return FormField[]
     */
    public function hookAdditionalCustomerFormFields($params)
    {
        $cfg = $this->getConfig();
        if (!(bool) $cfg['enabled'] || !$this->isProtectedPage()) {
            return [];
        }

        $guard = new SjbAntibotGuard($cfg);
        $token = $guard->issueTimingToken();

        $honeypot = (new FormField())
            ->setName(self::HP_FIELD)
            ->setType('text')
            ->setLabel($this->l('Sitio web'))
            ->setRequired(false)
            ->setValue('')
            ->setAutocompleteAttribute('off');

        $timing = (new FormField())
            ->setName(self::TS_FIELD)
            ->setType('hidden')
            ->setValue($token);

        static::debug('Campos antibot inyectados en formulario de cliente');

        return [$honeypot, $timing];
    }

    /**
     * Validación servidor: rate limit → honeypot → timing.
     * Mensaje genérico en todos los casos (no revelar la causa).
     *
     * @param array $params
     *
     * @return FormField[]
     */
    public function hookValidateCustomerFormFields($params)
    {
        $fields = isset($params['fields']) && is_array($params['fields']) ? $params['fields'] : [];

        $cfg = $this->getConfig();
        if (!(bool) $cfg['enabled'] || !$this->isProtectedPage()) {
            return $fields;
        }

        $guard = new SjbAntibotGuard($cfg);
        $guard->cleanupOldRows();

        $ip = $guard->getClientIp();
        $emailHash = $guard->hashEmail(Tools::getValue('email'));
        $errorMsg = $this->getGenericErrorMessage();

        $hpField = null;
        $tsValue = null;

        foreach ($fields as $field) {
            if (!($field instanceof FormField)) {
                continue;
            }
            if ($field->getName() === self::HP_FIELD) {
                $hpField = $field;
            }
            if ($field->getName() === self::TS_FIELD) {
                $tsValue = (string) $field->getValue();
            }
        }

        // Fallback por si el hidden no llega en el grupo de campos del módulo
        if ($tsValue === null || $tsValue === '') {
            $tsValue = (string) Tools::getValue(self::TS_FIELD);
        }

        $fail = function (string $reason) use ($guard, $ip, $emailHash, $hpField, $errorMsg, $fields) {
            $guard->recordFailure($ip, $reason, $emailHash);
            static::debug(sprintf('Bloqueo %s IP=%s', $reason, $ip), 2);

            if ($hpField instanceof FormField) {
                $hpField->addError($errorMsg);
            } elseif (!empty($fields[0]) && $fields[0] instanceof FormField) {
                $fields[0]->addError($errorMsg);
            }

            if (isset($this->context->controller) && is_object($this->context->controller)) {
                $this->context->controller->errors[] = $errorMsg;
            }

            return $fields;
        };

        if ($guard->isIpBlocked($ip)) {
            return $fail(SjbAntibotGuard::REASON_RATE);
        }

        $hpValue = $hpField instanceof FormField ? trim((string) $hpField->getValue()) : (string) Tools::getValue(self::HP_FIELD);
        if ($hpValue !== '') {
            return $fail(SjbAntibotGuard::REASON_HONEYPOT);
        }

        $timingFail = $guard->checkTiming($tsValue);
        if ($timingFail !== null) {
            return $fail($timingFail);
        }

        static::debug('Validación antibot OK IP=' . $ip);

        return $fields;
    }

    /**
     * CSS/JS para ocultar el honeypot (text + tabindex/aria via JS).
     */
    public function hookActionFrontControllerSetMedia($params)
    {
        $cfg = $this->getConfig();
        if (!(bool) $cfg['enabled'] || !$this->isProtectedPage()) {
            return;
        }

        $this->context->controller->addCSS($this->_path . 'views/css/front.css');
        $this->context->controller->addJS($this->_path . 'views/js/front.js');
    }

    /*
     * -------------------------------------------------------------------------
     * BACK OFFICE
     * -------------------------------------------------------------------------
     */

    public function getContent()
    {
        $output = '';

        if (Tools::isSubmit('submitSjbantibotConfig')) {
            $output .= $this->postProcess();
        }

        $output .= $this->context->smarty->fetch($this->local_path . 'views/templates/admin/info.tpl');
        $output .= $this->renderForm();

        return $output;
    }

    protected function postProcess()
    {
        $values = [
            'enabled' => (int) Tools::getValue('enabled'),
            'timing_min' => max(1, (int) Tools::getValue('timing_min')),
            'max_attempts' => max(1, (int) Tools::getValue('max_attempts')),
            'window_minutes' => max(1, (int) Tools::getValue('window_minutes')),
            'block_minutes' => max(1, (int) Tools::getValue('block_minutes')),
            'debug_enabled' => (int) Tools::getValue('debug_enabled'),
            'remove_data' => (int) Tools::getValue('remove_data'),
        ];

        foreach ($values as $key => $val) {
            Configuration::updateValue(self::PREFIX . Tools::strtoupper($key), $val);
        }

        static::$debugEnabled = (bool) $values['debug_enabled'];
        static::debug('Configuración guardada');

        return $this->displayConfirmation($this->l('Configuración actualizada.'));
    }

    protected function renderForm()
    {
        $fieldsForm = [
            'form' => [
                'legend' => [
                    'title' => $this->l('Configuración AntiBot'),
                    'icon' => 'icon-shield',
                ],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $this->l('Activar protección'),
                        'name' => 'enabled',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'enabled_on', 'value' => 1, 'label' => $this->l('Sí')],
                            ['id' => 'enabled_off', 'value' => 0, 'label' => $this->l('No')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Timing mínimo (segundos)'),
                        'name' => 'timing_min',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->l('Rechaza envíos más rápidos que este umbral.'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Máx. intentos por IP'),
                        'name' => 'max_attempts',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Ventana (minutos)'),
                        'name' => 'window_minutes',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->l('Periodo en el que se cuentan los intentos fallidos.'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Bloqueo (minutos)'),
                        'name' => 'block_minutes',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->l('Tiempo de bloqueo de la IP al superar el máximo.'),
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->l('Logging (PrestaShopLogger)'),
                        'name' => 'debug_enabled',
                        'is_bool' => true,
                        'desc' => $this->l('Escribe eventos en Parámetros avanzados → Logs.'),
                        'values' => [
                            ['id' => 'debug_on', 'value' => 1, 'label' => $this->l('Sí')],
                            ['id' => 'debug_off', 'value' => 0, 'label' => $this->l('No')],
                        ],
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->l('Borrar datos al desinstalar'),
                        'name' => 'remove_data',
                        'is_bool' => true,
                        'desc' => $this->l('Elimina tabla y configuración al desinstalar el módulo.'),
                        'values' => [
                            ['id' => 'remove_on', 'value' => 1, 'label' => $this->l('Sí')],
                            ['id' => 'remove_off', 'value' => 0, 'label' => $this->l('No')],
                        ],
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Guardar'),
                    'class' => 'btn btn-default pull-right',
                ],
            ],
        ];

        $helper = new HelperForm();
        $helper->show_toolbar = false;
        $helper->table = $this->table;
        $helper->module = $this;
        $helper->default_form_language = (int) Configuration::get('PS_LANG_DEFAULT');
        $helper->allow_employee_form_lang = (int) Configuration::get('PS_BO_ALLOW_EMPLOYEE_FORM_LANG');
        $helper->identifier = $this->identifier;
        $helper->submit_action = 'submitSjbantibotConfig';
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', false)
            . '&configure=' . $this->name
            . '&tab_module=' . $this->tab
            . '&module_name=' . $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');

        $cfg = $this->getConfig();
        $helper->tpl_vars = [
            'fields_value' => [
                'enabled' => (int) $cfg['enabled'],
                'timing_min' => (int) $cfg['timing_min'],
                'max_attempts' => (int) $cfg['max_attempts'],
                'window_minutes' => (int) $cfg['window_minutes'],
                'block_minutes' => (int) $cfg['block_minutes'],
                'debug_enabled' => (int) $cfg['debug_enabled'],
                'remove_data' => (int) $cfg['remove_data'],
            ],
            'languages' => $this->context->controller->getLanguages(),
            'id_language' => $this->context->language->id,
        ];

        return $helper->generateForm([$fieldsForm]);
    }
}
