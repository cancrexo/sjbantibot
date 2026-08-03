/**
 * Honeypot: tabindex, aria-hidden y clase en el contenedor.
 * Si hay error de validación, se muestra el bloque de error (no el input).
 */
(function () {
    'use strict';

    function enhanceHoneypot() {
        var inputs = document.querySelectorAll('input[name="company_url"]');
        if (!inputs.length) {
            return;
        }

        Array.prototype.forEach.call(inputs, function (input) {
            input.setAttribute('tabindex', '-1');
            input.setAttribute('aria-hidden', 'true');
            input.setAttribute('autocomplete', 'off');
            if (!input.getAttribute('type')) {
                input.setAttribute('type', 'text');
            }

            var group = input.closest
                ? input.closest('.form-group, .form-group.row, .form-group.row.has-error')
                : null;

            if (!group) {
                group = input.parentElement;
                while (group && group !== document.body) {
                    if (group.classList && (group.classList.contains('form-group') || group.classList.contains('form-group'))) {
                        break;
                    }
                    // Subir hasta encontrar un contenedor con label+input
                    if (group.querySelector && group.querySelector('label') && group !== input.parentElement) {
                        break;
                    }
                    group = group.parentElement;
                }
            }

            if (!group || group === document.body) {
                // Último recurso: ocultar solo el input
                input.style.position = 'absolute';
                input.style.left = '-10000px';
                return;
            }

            group.classList.add('sjbantibot-hp');

            var hasError = group.classList.contains('has-error')
                || group.querySelector('.help-block, .alert-danger, .form-error, ul li');

            if (hasError) {
                group.classList.add('sjbantibot-hp-show-error');
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', enhanceHoneypot);
    } else {
        enhanceHoneypot();
    }
})();
