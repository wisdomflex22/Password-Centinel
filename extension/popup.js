// ======================================================================
// --- CORE SECURITY: WEB CRYPTO API IMPLEMENTATION (AES-GCM & PBKDF2) ---
// ======================================================================

class CryptoManager {
    static get masterKey() {
        return this._masterKey;
    }

    static set masterKey(key) {
        this._masterKey = key;
    }

    // Algoritmo de derivación de clave
    static get keyDerivationAlgorithm() {
        return {
            name: "PBKDF2",
            salt: new Uint8Array([19, 107, 24, 196, 178, 14, 151, 14, 219, 137, 7, 203, 115, 207, 24, 185]), // Sal estática para consistencia
            iterations: 100000, // Número alto de iteraciones
            hash: "SHA-256",
        };
    }

    // Algoritmo de cifrado
    static get encryptionAlgorithm() {
        return { name: "AES-GCM", iv: null, tagLength: 128 };
    }

    // 1. Derivar la clave criptográfica a partir de la Clave Maestra
    static async deriveKey(masterKey) {
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(masterKey),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            this.keyDerivationAlgorithm,
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // 2. Cifrado Seguro con AES-GCM
    static async encrypt(text) {
        if (!this._masterKey) throw new Error("Clave Maestra no establecida para cifrar.");

        const derivedKey = await this.deriveKey(this._masterKey);
        const iv = crypto.getRandomValues(new Uint8Array(16)); // Vector de inicialización único
        
        const algo = this.encryptionAlgorithm;
        algo.iv = iv;

        const cipherBuffer = await crypto.subtle.encrypt(
            algo,
            derivedKey,
            new TextEncoder().encode(text)
        );

        // Concatenar IV y el texto cifrado, luego convertir a Base64 para almacenar
        const fullCipher = new Uint8Array(iv.byteLength + cipherBuffer.byteLength);
        fullCipher.set(iv, 0);
        fullCipher.set(new Uint8Array(cipherBuffer), iv.byteLength);

        return btoa(String.fromCharCode.apply(null, fullCipher));
    }

    // 3. Descifrado Seguro con AES-GCM
    static async decrypt(cipher) {
        if (!this._masterKey) throw new Error("Clave Maestra no establecida para descifrar.");

        const derivedKey = await this.deriveKey(this._masterKey);

        const binaryStr = atob(cipher);
        const fullCipher = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            fullCipher[i] = binaryStr.charCodeAt(i);
        }

        const iv = fullCipher.slice(0, 16); // IV son los primeros 16 bytes
        const cipherText = fullCipher.slice(16);

        const algo = this.encryptionAlgorithm;
        algo.iv = iv;

        try {
            const decryptedBuffer = await crypto.subtle.decrypt(
                algo,
                derivedKey,
                cipherText
            );
            return new TextDecoder().decode(decryptedBuffer);
        } catch (e) {
            console.error("Fallo al descifrar (Clave Maestra incorrecta o datos corruptos):", e);
            throw new Error("Clave Maestra incorrecta o datos corruptos.");
        }
    }
}


// ======================================================================
// --- CORE: PASSWORD CENTINEL CLASS ---
// Se han corregido los caracteres especiales (p. ej., "Puntuación")
// ======================================================================

class PasswordSentinel {
    constructor() {
        this.history = [];
        this.vault = [];
        this.masterKeyLocked = true;
        this.initListeners();
        this.loadInitialState();
    }

    // --- INITIALIZATION & STATE ---

    async loadInitialState() {
        const { history = [] } = await chrome.storage.local.get('history');
        this.history = history;
        this.updatePasswordHistory();
        
        const { masterKey } = await chrome.storage.local.get('masterKey');
        if (masterKey) {
            // Mostrar banner de desbloqueo
            this.switchTab('vault');
            document.getElementById('masterKeyBanner').style.display = 'flex';
            document.getElementById('setMasterKeyBtn').textContent = 'Cambiar Clave Maestra';
            document.getElementById('lockVaultBtn').style.display = 'block';
        } else {
            // No hay clave, pedir configuración
            this.switchTab('settings');
        }

        this.calculateHealthScore();
    }

    initListeners() {
        // Tab Switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Analyzer
        document.getElementById('passwordInput').addEventListener('input', (e) => this.analyzePassword(e.target.value));
        document.getElementById('checkBreach').addEventListener('click', () => this.checkBreach(document.getElementById('passwordInput').value));

        // Generator
        document.getElementById('generatePassword').addEventListener('click', () => this.generateAndDisplayPassword());
        document.getElementById('copyPassword').addEventListener('click', () => this.copyPassword());

        // History (UX)
        document.getElementById('historySearch').addEventListener('input', (e) => this.updatePasswordHistory(e.target.value));
        
        // Vault/Master Key (Seguridad y Alto Impacto)
        document.getElementById('setupMasterKeyBtn').addEventListener('click', () => this.switchTab('settings'));
        document.getElementById('goToVaultBtn').addEventListener('click', () => this.switchTab('vault'));
        document.getElementById('setMasterKeyBtn').addEventListener('click', () => this.setMasterKey());
        document.getElementById('unlockVaultBtn').addEventListener('click', () => this.unlockVault());
        document.getElementById('lockVaultBtn').addEventListener('click', () => this.lockVault());
    }

    // --- TAB MANAGEMENT ---
    
    switchTab(tabId) {
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });

        document.getElementById(tabId).classList.add('active');
        document.querySelector(`.tab-button[data-tab="${tabId}"]`).classList.add('active');

        // Acciones específicas al cambiar de pestaña
        if (tabId === 'vault') {
            this.renderVault();
        }
        if (tabId === 'health') {
            this.calculateHealthScore();
        }
    }

    // --- STRENGTH ANALYSIS & HIBP ---

    // La misma lógica implementada en content.js
    analyzeStrength(password) {
        // ... (La lógica de analyzeStrength es idéntica a la del archivo anterior)
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
        // --- (Fin de la lógica analyzeStrength) ---
    }


    analyzePassword(password) {
        const result = this.analyzeStrength(password);
        const indicator = document.getElementById('strengthIndicator');
        const suggestionsEl = document.getElementById('suggestions');

        // Visualización de la Barra de Progreso
        const maxScore = 7; 
        const progress = (result.score / maxScore) * 100;
        indicator.style.width = `${progress}%`;
        indicator.style.backgroundColor = result.color;
        
        // Añadir el texto directamente dentro de la barra si es lo suficientemente ancha
        if (progress > 50) {
            indicator.textContent = result.strength;
            indicator.style.color = '#fff';
        } else {
            indicator.textContent = '';
        }
        
        // Mostrar sugerencias
        if (result.suggestions.length > 0) {
            suggestionsEl.innerHTML = `**Sugerencias:** ${result.suggestions.join(', ')}`;
            suggestionsEl.style.color = result.color === '#28a745' ? '#000' : result.color; // Evitar verde muy fuerte en texto
        } else {
            suggestionsEl.textContent = '¡Excelente! Contraseña fuerte.';
            suggestionsEl.style.color = '#28a745';
        }
    }

    checkBreach(password) {
        const resultBox = document.getElementById('breachResult');
        resultBox.innerHTML = 'Verificando con HIBP...';

        chrome.runtime.sendMessage({ action: 'checkBreach', password: password }, (response) => {
            if (response && response.breached) {
                resultBox.innerHTML = `⚠️ **¡Comprometida!** Encontrada ${response.count.toLocaleString()} veces en brechas conocidas. **¡Cámbiala inmediatamente!**`;
                resultBox.style.backgroundColor = '#f8d7da'; 
                resultBox.style.color = '#721c24';
            } else if (response) {
                resultBox.innerHTML = '✅ ¡Parece segura! No encontrada en brechas conocidas.';
                resultBox.style.backgroundColor = '#d4edda'; 
                resultBox.style.color = '#155724';
            } else {
                 resultBox.innerHTML = 'Error al contactar al servicio de verificación.';
                 resultBox.style.backgroundColor = '#fefefe';
                 resultBox.style.color = '#856404';
            }
        });
    }

    // --- GENERATOR AND UX IMPROVEMENTS ---
    
    // Generador con opciones avanzadas de símbolos
    generateSecurePassword(length, includeUpper, includeNumbers, includeSymbols, customSymbols) {
        let chars = '';
        chars += 'abcdefghijklmnopqrstuvwxyz';
        if (includeUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (includeNumbers) chars += '0123456789';
        
        let symbols = '!@#$%^&*()_+~`|}{[]\:;?><,./-='; // Símbolos por defecto
        if (customSymbols && customSymbols.trim().length > 0) {
             symbols = customSymbols.trim(); // Usar los personalizados si se proporcionan
        }
        if (includeSymbols) chars += symbols;
        
        if (chars.length === 0) return 'Error: Selecciona tipos de caracteres.'; // Evitar bucle infinito

        let password = '';
        const secureRandom = (max) => Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / (0xffffffff + 1) * max);
        
        for (let i = 0; i < length; i++) {
            password += chars.charAt(secureRandom(chars.length));
        }
        
        // Asegurar que al menos un carácter de cada tipo requerido esté presente
        const ensureCharacterType = (charSet) => {
             if (charSet.length > 0) {
                const char = charSet.charAt(secureRandom(charSet.length));
                const pos = secureRandom(length);
                password = password.substring(0, pos) + char + password.substring(pos + 1);
            }
        };

        if (includeUpper) ensureCharacterType('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
        if (includeNumbers) ensureCharacterType('0123456789');
        if (includeSymbols) ensureCharacterType(symbols);
        
        return password;
    }

    generateAndDisplayPassword() {
        const length = parseInt(document.getElementById('lengthInput').value);
        const includeUpper = document.getElementById('includeUpper').checked;
        const includeNumbers = document.getElementById('includeNumbers').checked;
        const includeSymbols = document.getElementById('includeSymbols').checked;
        const customSymbols = document.getElementById('customSymbols').value;

        const password = this.generateSecurePassword(length, includeUpper, includeNumbers, includeSymbols, customSymbols);
        document.getElementById('generatedPassword').value = password;

        const result = this.analyzeStrength(password);
        
        // Guardar en el historial
        this.history.push({ 
            password: password, 
            strength: result.strength, 
            date: new Date().toLocaleDateString(),
            score: result.score
        });
        
        this.history = this.history.slice(-50); // Limitar a 50 elementos

        chrome.storage.local.set({ history: this.history }, () => {
             this.updatePasswordHistory();
        });
    }

    copyPassword() {
        const passwordInput = document.getElementById('generatedPassword');
        passwordInput.select();
        document.execCommand('copy');
        alert('Contraseña copiada al portapapeles.');
    }

    // Filtro y Búsqueda en el Historial (UX)
    updatePasswordHistory(searchTerm = '') {
        const list = document.getElementById('passwordHistoryList');
        list.innerHTML = '';
        const lowerCaseSearch = searchTerm.toLowerCase();

        this.history
            .slice() 
            .reverse() 
            .filter(item => 
                searchTerm === '' || 
                item.password.toLowerCase().includes(lowerCaseSearch) ||
                item.strength.toLowerCase().includes(lowerCaseSearch)
            )
            .forEach((item) => {
                const li = document.createElement('li');
                
                const passwordDisplay = document.createElement('input');
                passwordDisplay.type = 'text';
                passwordDisplay.value = '**********'; 
                passwordDisplay.readOnly = true;

                const details = document.createElement('div');
                details.className = 'history-item-details';
                details.innerHTML = `
                    <p><strong>${item.strength}</strong> - ${item.date}</p>
                    <p>Contraseña: ${passwordDisplay.outerHTML}</p>
                `;
                
                const toggleButton = document.createElement('button');
                toggleButton.textContent = 'Mostrar';
                toggleButton.addEventListener('click', () => {
                    const inputEl = li.querySelector('.history-item-details input');
                    if (toggleButton.textContent === 'Mostrar') {
                        inputEl.value = item.password;
                        toggleButton.textContent = 'Ocultar';
                    } else {
                        inputEl.value = '**********';
                        toggleButton.textContent = 'Mostrar';
                    }
                });
                
                const copyButton = document.createElement('button');
                copyButton.textContent = 'Copiar';
                copyButton.addEventListener('click', () => {
                    navigator.clipboard.writeText(item.password);
                    copyButton.textContent = 'Copiado!';
                    setTimeout(() => copyButton.textContent = 'Copiar', 1500);
                });

                li.appendChild(details);
                const actions = document.createElement('div');
                actions.className = 'history-item-actions';
                actions.appendChild(toggleButton);
                actions.appendChild(copyButton);
                li.appendChild(actions);

                list.appendChild(li);
            });

        if (list.childElementCount === 0 && searchTerm !== '') {
            list.innerHTML = '<li style="justify-content: center;">No se encontraron resultados.</li>';
        } else if (list.childElementCount === 0 && this.history.length === 0) {
            list.innerHTML = '<li style="justify-content: center;">El historial está vacío.</li>';
        }
    }


    // --- VAULT, MASTER KEY, HEALTH ---
    
    // --- Master Key Management (¡AHORA SEGURO!) ---
    async setMasterKey() {
        const newKey = document.getElementById('newMasterKeyInput').value;
        const statusEl = document.getElementById('masterKeyStatus');
        statusEl.textContent = '';

        if (newKey.length < 12) {
            statusEl.textContent = 'La Clave Maestra debe tener al menos 12 caracteres (recomendado).';
            statusEl.classList.add('error-message');
            return;
        }

        // Almacenar la clave como texto plano SOLO para la verificación de desbloqueo,
        // la criptografía se basa en la derivación de clave.
        await chrome.storage.local.set({ masterKey: newKey });
        
        statusEl.textContent = '¡Clave Maestra guardada con éxito! La Bóveda está lista para usar.';
        statusEl.classList.remove('error-message');
        statusEl.classList.add('success-message');
        
        document.getElementById('masterKeyBanner').style.display = 'none'; 
        document.getElementById('setMasterKeyBtn').textContent = 'Cambiar Clave Maestra';
        document.getElementById('lockVaultBtn').style.display = 'block';
        
        this.lockVault();
        this.calculateHealthScore();
    }

    async unlockVault() {
        const keyInput = document.getElementById('masterKeyUnlockInput');
        const errorEl = document.getElementById('unlockError');
        const key = keyInput.value;
        errorEl.textContent = 'Verificando...';

        const { masterKey } = await chrome.storage.local.get('masterKey');
        
        if (key !== masterKey) {
            errorEl.textContent = 'Clave Maestra incorrecta.';
            keyInput.value = '';
            return;
        }

        try {
            // Intenta derivar la clave para asegurar que es usable antes de desbloquear
            await CryptoManager.deriveKey(key); 
            
            // Clave correcta, establecer la clave en CryptoManager
            CryptoManager.masterKey = key;
            this.masterKeyLocked = false;
            
            // Mostrar la bóveda
            document.getElementById('masterKeyLock').style.display = 'none';
            document.getElementById('credentialListContainer').style.display = 'block';
            document.getElementById('masterKeyBanner').style.display = 'none';
            errorEl.textContent = '';
            
            this.loadVault();
        } catch (e) {
             errorEl.textContent = 'Error crítico de criptografía. Asegúrate de que la clave es correcta.';
             keyInput.value = '';
        }
    }
    
    lockVault() {
        CryptoManager.masterKey = null; // Eliminar la clave de la memoria volátil
        this.masterKeyLocked = true;
        this.vault = []; // Limpiar las credenciales descifradas de la memoria

        // Mostrar el formulario de desbloqueo y ocultar la lista
        document.getElementById('masterKeyLock').style.display = 'block';
        document.getElementById('credentialListContainer').style.display = 'none';
        document.getElementById('masterKeyUnlockInput').value = '';
        document.getElementById('unlockError').textContent = '';
        
        this.renderVault();
        this.calculateHealthScore();
    }


    // --- Vault Management ---
    
    async loadVault() {
        const list = document.getElementById('credentialList');
        if (this.masterKeyLocked) {
            list.innerHTML = '<li style="justify-content: center;">Bóveda bloqueada. Desbloquea para ver credenciales.</li>';
            return;
        }

        list.innerHTML = '<li style="justify-content: center;">Descifrando credenciales...</li>';
        
        const { vault: encryptedVault = [] } = await chrome.storage.local.get('vault');
        
        // Descifrar todas las contraseñas
        this.vault = await Promise.all(encryptedVault.map(async item => {
            try {
                item.decryptedPassword = await CryptoManager.decrypt(item.password); 
            } catch (e) {
                console.error("Error al descifrar un ítem de la bóveda:", e);
                item.decryptedPassword = 'ERROR_DE_DESCIFRADO (Clave incorrecta o fallo en el IV/Tag)';
            }
            return item;
        }));

        this.renderVault();
        this.calculateHealthScore();
    }

    renderVault() {
        if (this.masterKeyLocked) return;

        const list = document.getElementById('credentialList');
        list.innerHTML = '';
        
        if (this.vault.length === 0) {
             list.innerHTML = '<li style="justify-content: center;">La bóveda está vacía. Guarda tu primera credencial.</li>';
             return;
        }

        this.vault.forEach(item => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div class="history-item-details">
                    <p><strong>URL:</strong> ${item.url}</p>
                    <p><strong>Usuario:</strong> ${item.username}</p>
                    <p><strong>Contraseña:</strong> <input type="text" value="********" data-decrypted="${item.decryptedPassword}" readonly></p>
                </div>
                <div class="history-item-actions">
                    <button class="toggle-pass-vault">Mostrar</button>
                    <button class="copy-pass-vault">Copiar</button>
                    <button class="delete-pass-vault" data-id="${item.id}">Eliminar</button>
                    <button class="autofill-pass-vault" data-id="${item.id}">Autorellenar</button>
                </div>
            `;
            
            // Listeners dinámicos
            li.querySelector('.toggle-pass-vault').addEventListener('click', (e) => this.togglePasswordVisibility(e.target));
            li.querySelector('.copy-pass-vault').addEventListener('click', (e) => this.copyVaultPassword(e.target.closest('li')));
            li.querySelector('.delete-pass-vault').addEventListener('click', (e) => this.deleteCredential(e.target.dataset.id));
            li.querySelector('.autofill-pass-vault').addEventListener('click', (e) => this.autofillCredential(e.target.dataset.id));

            list.appendChild(li);
        });
    }
    
    togglePasswordVisibility(button) {
        const input = button.closest('li').querySelector('input[type="text"]');
        if (button.textContent === 'Mostrar') {
            input.value = input.dataset.decrypted;
            button.textContent = 'Ocultar';
        } else {
            input.value = '********';
            button.textContent = 'Mostrar';
        }
    }

    copyVaultPassword(listItem) {
        const password = listItem.querySelector('input[type="text"]').dataset.decrypted;
        navigator.clipboard.writeText(password);
        const button = listItem.querySelector('.copy-pass-vault');
        button.textContent = 'Copiado!';
        setTimeout(() => button.textContent = 'Copiar', 1500);
    }
    
    async deleteCredential(id) {
        if (!confirm('¿Estás seguro de que quieres eliminar esta credencial de la bóveda?')) return;
        
        const numericId = parseInt(id);
        const { vault: currentVault } = await chrome.storage.local.get('vault');
        
        const newVault = currentVault.filter(item => item.id !== numericId);
        
        await chrome.storage.local.set({ vault: newVault });
        this.loadVault(); 
    }
    
    autofillCredential(id) {
        const credential = this.vault.find(item => item.id == id);
        if (!credential) return;

        // Enviar mensaje al content script de la pestaña activa para rellenar
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            // El content script buscará el campo de contraseña
            chrome.tabs.sendMessage(tabs[0].id, { 
                action: 'fillField', 
                password: credential.decryptedPassword, 
                username: credential.username 
            });
        });
        alert(`Contraseña para ${credential.username}@${credential.url} enviada para Autorelleno.`);
    }


    // --- Health Score Calculation (UX) ---
    
    async calculateHealthScore() {
        const { vault: encryptedVault = [] } = await chrome.storage.local.get('vault');
        
        let decryptedPasswords = [];
        if (!this.masterKeyLocked) {
             decryptedPasswords = this.vault.map(item => item.decryptedPassword).filter(p => p && p !== 'ERROR_DE_DESCIFRADO (Clave incorrecta o fallo en el IV/Tag)');
        }
        
        let weakCount = 0;
        let reuseCount = 0;
        let breachCount = 0;
        
        if (decryptedPasswords.length > 0) {
            // 1. Detección de Fortaleza y Reutilización
            const passwordsSeen = {};
            const foundReused = new Set();
            
            decryptedPasswords.forEach(p => {
                const result = this.analyzeStrength(p);
                if (result.score < 3) {
                    weakCount++;
                }
            });
            
            // Recorrer el vault para detectar reutilización
            this.vault.forEach(item => {
                const p = item.decryptedPassword;
                if (p && p !== 'ERROR_DE_DESCIFRADO (Clave incorrecta o fallo en el IV/Tag)') {
                    if (passwordsSeen[p] && item.url !== passwordsSeen[p]) {
                        foundReused.add(p);
                    }
                    passwordsSeen[p] = item.url;
                }
            });

            reuseCount = foundReused.size;
            
            // 2. Simulación de Detección de Brechas
            decryptedPasswords.forEach(p => {
                 if (p.includes('123456') || p.includes('password') || p.includes('qwerty')) {
                    breachCount++;
                }
            });
        }


        // 3. Puntuación Global (Heurística)
        let healthScore = 100 - (weakCount * 10) - (reuseCount * 20) - (breachCount * 50);
        healthScore = Math.max(0, healthScore);
        
        let healthLevel = 'No Aplicable';
        let healthColor = '#6c757d'; // Gris por defecto
        
        if (encryptedVault.length > 0) {
            if (this.masterKeyLocked) {
                healthLevel = 'Bloqueado';
            } else if (healthScore > 85) {
                healthLevel = 'Excelente';
                healthColor = '#28a745';
            } else if (healthScore > 60) {
                healthLevel = 'Buena';
                healthColor = '#ffc107';
            } else {
                healthLevel = 'Pobre';
                healthColor = '#dc3545';
            }
        } else {
             healthLevel = 'Vacío';
        }

        // 4. Actualizar UI
        document.getElementById('vaultCount').textContent = encryptedVault.length;
        document.getElementById('breachCount').textContent = breachCount;
        document.getElementById('reuseCount').textContent = reuseCount;
        document.getElementById('weakCount').textContent = weakCount;
        
        const overallHealthEl = document.getElementById('overallHealth');
        overallHealthEl.textContent = healthLevel;
        overallHealthEl.style.backgroundColor = healthColor;
        overallHealthEl.style.color = (healthColor === '#ffc107') ? '#333' : '#fff'; // Texto oscuro para fondo amarillo/naranja
    }
}

// Inicialización
document.addEventListener('DOMContentLoaded', () => {
    window.passwordSentinel = new PasswordSentinel();
});