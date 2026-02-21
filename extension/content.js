/**
 * Password Centinel - content.js
 * * Este script se inyecta en todas las páginas web para:
 * 1. Analizar la fortaleza de las contraseñas en tiempo real.
 * 2. Interceptar formularios de inicio de sesión para la captura de credenciales.
 */

// --- 1. MEJORA DE SEGURIDAD: ANÁLISIS DE FORTALEZA (Simulación de Zxcvbn) ---
// (Esta función permanece igual a la última versión para consistencia)
function analyzeStrength(password) {
    if (!password || password.length === 0) {
        return { score: 0, strength: 'Ninguna', color: 'gray', suggestions: [] };
    }

    let score = 0;
    let suggestions = [];

    // Longitud
    const len = password.length;
    if (len < 8) {
        suggestions.push("Aumenta la longitud (mínimo 8 caracteres).");
    } else if (len >= 15) {
        score += 2;
    } else if (len >= 12) {
        score += 1;
    }

    // Caracteres: Minúsculas, Mayúsculas, Números, Símbolos
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9\s]/.test(password);

    if (hasLower) score += 1; else suggestions.push("Incluye letras minúsculas.");
    if (hasUpper) score += 1; else suggestions.push("Incluye letras mayúsculas.");
    if (hasNumber) score += 1; else suggestions.push("Incluye números.");
    if (hasSymbol) score += 1; else suggestions.push("Incluye símbolos.");

    // Detección de patrones comunes/diccionario (simulado)
    const currentYear = new Date().getFullYear().toString();
    const commonPatterns = ['password', '123456', 'qwerty', 'admin', currentYear];
    if (commonPatterns.some(p => password.toLowerCase().includes(p))) {
        score = Math.max(0, score - 2); // Penalización severa
        suggestions.push("Evita patrones comunes o palabras de diccionario.");
    }
    
    // Detección de repetición (ej. 'aaaa', '1111')
    if (/(.)\1{3,}/.test(password)) {
        score = Math.max(0, score - 1);
        suggestions.push("Evita la repetición de caracteres.");
    }

    // Mapeo del Score a Fortaleza y Color
    let strength = 'Muy Débil';
    let color = '#dc3545'; // Rojo
    if (score >= 7) {
        strength = 'Excelente';
        color = '#28a745'; // Verde Fuerte
    } else if (score >= 5) {
        strength = 'Fuerte';
        color = '#20c997'; // Verde medio
    } else if (score >= 3) {
        strength = 'Moderada';
        color = '#ffc107'; // Amarillo
    } else if (score >= 1) {
        strength = 'Débil';
        color = '#fd7e14'; // Naranja

    }

    return { score, strength, color, suggestions };
}


// --- 2. GESTIÓN DE INDICADORES DE FORTALEZA (CORRECCIÓN DE CRASH) ---

// Se añade una clase única al indicador para identificarlo fácilmente
const INDICATOR_CLASS = 'password-centinel-indicator-bar';

function createStrengthIndicator() {
    let indicator = document.createElement('div');
    indicator.className = INDICATOR_CLASS;
    indicator.style.height = '5px'; // Hacemos el indicador más pequeño y discreto
    indicator.style.marginTop = '2px';
    indicator.style.borderRadius = '2px';
    indicator.style.transition = 'width 0.3s, background-color 0.3s';
    return indicator;
}

function updateIndicator(input, result) {
    // Buscar el contenedor de input si existe (para SPAs)
    const container = input.closest('div, p, li'); 
    if (!container) return; // Salir si no hay un contenedor padre

    let existingIndicator = container.querySelector(`.${INDICATOR_CLASS}`);
    
    if (!existingIndicator) {
        // Si no existe, crearlo
        existingIndicator = createStrengthIndicator();
        // Insertar justo después del input
        if (input.parentNode) {
            input.parentNode.insertBefore(existingIndicator, input.nextSibling);
        } else {
            // Caso de borde, insertamos al final del contenedor
            container.appendChild(existingIndicator);
        }
    }
    
    // Actualizar el estado del indicador
    const progress = (result.score / 7) * 100;
    existingIndicator.style.width = `${progress}%`;
    existingIndicator.style.backgroundColor = result.color;
    
    // Añadir el texto del resultado como un elemento hermano para evitar que interfiera con el layout del input
    let strengthText = container.querySelector('.password-centinel-strength-text');
    if (!strengthText) {
        strengthText = document.createElement('span');
        strengthText.className = 'password-centinel-strength-text';
        strengthText.style.fontSize = '0.75em';
        strengthText.style.display = 'block';
        strengthText.style.color = result.color;
        
        // Insertar después del indicador de barra
        existingIndicator.parentNode.insertBefore(strengthText, existingIndicator.nextSibling);
    }
    
    strengthText.textContent = `Fortaleza: ${result.strength}`;
    strengthText.style.color = result.color;
}

// --- 3. FUNCIONES DE CAPTURA DE CREDENCIALES ---

function findCredentialsInForm(form) {
    let usernameField = null;
    let passwordField = null;

    // 1. Buscar campos de contraseña
    const passwordInputs = form.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0) {
        passwordField = passwordInputs[0]; 
    }

    // 2. Buscar campos de usuario (heurística)
    const textInputs = form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
    for (let input of textInputs) {
        const name = input.name ? input.name.toLowerCase() : '';
        const id = input.id ? input.id.toLowerCase() : '';

        if (name.includes('user') || name.includes('login') || name.includes('email') || name.includes('mail') ||
            id.includes('user') || id.includes('login') || id.includes('email') || id.includes('mail')) {
            usernameField = input;
            break;
        }
    }
    
    // Heurística simple: buscar campo de texto anterior si no se encuentra nada
    if (!usernameField && passwordField) {
        let prevElement = passwordField.previousElementSibling;
        if (prevElement && prevElement.tagName === 'INPUT' && prevElement.type !== 'password') {
            usernameField = prevElement;
        }
    }

    return { usernameField, passwordField };
}

// Listener de envío de formulario para captura de credenciales
function handleFormSubmission(event) {
    const form = event.target;
    const { usernameField, passwordField } = findCredentialsInForm(form);

    if (usernameField && passwordField && usernameField.value && passwordField.value) {
        
        // Evitar guardar formularios de cambio de contraseña donde user y pass son iguales
        if (usernameField.value === passwordField.value) return; 

        // Enviar al background script para que guarde (con confirmación del usuario)
        chrome.runtime.sendMessage({
            action: 'captureAndSave',
            url: window.location.hostname,
            username: usernameField.value,
            password: passwordField.value
        }, (response) => {
            if (response && response.success) {
                // Notificación simple de éxito
            }
        });
    }
}

// --- 4. MEJORA: ANÁLISIS HEURÍSTICO DE CAMPOS Y ENHANCEMENT (CORRECCIÓN DE CRASH) ---

// Se utiliza un Set para evitar re-procesar los mismos inputs y añadir múltiples listeners
const enhancedInputs = new WeakSet();

function findAndEnhancePasswordFields() {
    // 1. Campos type="password"
    document.querySelectorAll('input[type="password"]').forEach((input, index) => {
        
        // **CORRECCIÓN:** Verificar si el input ya tiene listeners/indicadores
        if (enhancedInputs.has(input)) {
            // Si ya fue mejorado, solo analizamos si tiene valor por si fue autocompletado después de la carga
            if (input.value) {
                const result = analyzeStrength(input.value);
                updateIndicator(input, result);
            }
            return;
        }

        // Añadir un ID para autocompletado si no lo tiene
        if (!input.id) input.id = `centinel-pass-${index}`;
        
        // Análisis en tiempo real al escribir
        input.addEventListener('input', (e) => {
            // **CORRECCIÓN:** Asegurar que el target existe (puede ser nulo si el campo se elimina)
            if (e.target) {
                const result = analyzeStrength(e.target.value);
                updateIndicator(e.target, result);
            }
        });
        
        // Si tiene un valor al cargar (ej. autocompletado del navegador), analizar
        if (input.value) {
            const result = analyzeStrength(input.value);
            updateIndicator(input, result);
        }
        
        enhancedInputs.add(input); // Marcar como procesado
    });

    // 2. Análisis heurístico de campos text/email que DEBERÍAN ser password
    document.querySelectorAll('input:not([type="password"])').forEach(input => {
        const name = input.name ? input.name.toLowerCase() : '';
        const id = input.id ? input.id.toLowerCase() : '';
        
        if ((name.includes('pass') || id.includes('pass') || name.includes('pwd') || id.includes('pwd')) && input.type !== 'hidden') {
            
            // Si el campo de contraseña potencial no está configurado como 'password'
            if (input.type === 'text' || input.type === 'email') {
                input.style.border = '2px solid #FFA500'; // Advertencia visual Naranja
                input.title = 'Password Centinel: Este campo parece ser de contraseña pero es de tipo ' + input.type + '. Considere cambiarlo a "password".';
            }
        }
    });

    // 3. Listener para la captura de credenciales
    document.querySelectorAll('form').forEach(form => {
        // Asegurarse de no añadir el listener dos veces (aunque removeEventListener ayuda, es mejor chequear)
        form.removeEventListener('submit', handleFormSubmission); 
        form.addEventListener('submit', handleFormSubmission);
    });
}


// --- 5. GESTIÓN DEL MENSAJE DE RELLENADO ---
function handleFillField(input, password, username) {
    if (!input) return;
    
    // Lógica para rellenar la contraseña
    input.focus();
    input.value = password;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    
    // Si se proporciona un nombre de usuario, intentar rellenar el campo anterior/relacionado
    if (username) {
        const form = input.closest('form');
        if (form) {
             const { usernameField } = findCredentialsInForm(form);
             if (usernameField) {
                 usernameField.focus();
                 usernameField.value = username;
                 usernameField.dispatchEvent(new Event('input', { bubbles: true }));
                 usernameField.dispatchEvent(new Event('change', { bubbles: true }));
             }
        }
    }
}

// Listener para mensajes del popup o background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    
    // a) Rellenado de un campo específico (desde la bóveda/popup)
    if (request.action === 'fillField') {
        let input = document.getElementById(request.targetElementId); 
        
        if (!input) {
            input = document.querySelector('input[type="password"]');
        }

        if (input) {
            handleFillField(input, request.password, request.username);
        }
    }
    
    // b) Generar y rellenar (desde el Menú Contextual)
    if (request.action === 'contextMenuGenerate') {
        const input = document.getElementById(request.targetElementId);
        if (input) {
            // Generación simple (idealmente esto se haría con la lógica de popup.js)
            const newPassword = 'CentinelGen' + Math.random().toString(36).slice(-8);
            handleFillField(input, newPassword, null);
            alert('Password Centinel: Nueva contraseña generada y rellenada en el campo. ¡Recuerda guardarla!');
        }
    }
    
    // c) Analizar campo (desde el Menú Contextual)
     if (request.action === 'contextMenuAnalyze') {
        const input = document.getElementById(request.targetElementId);
        if (input && input.value) {
            const result = analyzeStrength(input.value);
            alert(`Password Centinel:\nFortaleza: ${result.strength}\nSugerencias: ${result.suggestions.join(', ')}`);
        }
    }
    
    // d) Ejecutar al cargar la página (existente)
    if (request.action === "pageLoaded") {
         findAndEnhancePasswordFields();
    }
});


// Ejecución inicial y observador
findAndEnhancePasswordFields();

// Usar MutationObserver para detectar formularios cargados dinámicamente
// **CORRECCIÓN:** Se hace un chequeo más rápido antes de invocar findAndEnhancePasswordFields
const observer = new MutationObserver((mutationsList, observer) => {
    // Optimización: solo correr si se añade un elemento
    const addedNodes = mutationsList.some(mutation => mutation.addedNodes.length > 0);
    if (addedNodes) {
        findAndEnhancePasswordFields();
    }
});

// **CORRECCIÓN:** Asegurarse de que body exista antes de observarlo.
if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
} else {
    // Si no hay body, usar el documento (caso raro, pero más seguro)
    observer.observe(document.documentElement, { childList: true, subtree: true });
}