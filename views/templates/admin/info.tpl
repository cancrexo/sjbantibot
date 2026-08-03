{*
 * Panel informativo del módulo sjbantibot
 *
 * @author Daniel "Cancrexo" Prol <cancrexo@gmail.com>
 *}
<div class="panel" id="sjbantibot-info">
    <div class="panel-heading">
        <i class="icon-info-circle"></i> {l s='Información' mod='sjbantibot'}
    </div>
    <div class="panel-body">
        <p>{l s='Protección 100%% local contra bots en el registro de clientes (página de registro y checkout).' mod='sjbantibot'}</p>
        <ul>
            <li><strong>Honeypot</strong> — {l s='campo oculto inocente; si viene relleno, se rechaza.' mod='sjbantibot'}</li>
            <li><strong>Timing</strong> — {l s='rechaza envíos demasiado rápidos (token HMAC local con _COOKIE_KEY_).' mod='sjbantibot'}</li>
            <li><strong>Rate limit</strong> — {l s='limita intentos fallidos por IP y bloquea temporalmente.' mod='sjbantibot'}</li>
        </ul>
        <p class="text-muted">
            {l s='Sin reCAPTCHA, Turnstile ni peticiones externas. El mensaje de error es genérico a propósito.' mod='sjbantibot'}
        </p>
    </div>
</div>
