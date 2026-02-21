// --- FUNCIONES DE BASE DE DATOS Y GESTIÓN DE LA BÓVEDA (AHORA ASÍNCRONAS Y SEGURAS) ---

// Algoritmo de derivación de clave (debe ser el mismo que en popup.js)
const keyDerivationAlgorithm = {
    name: "PBKDF2",
    salt: new Uint8Array([19, 107, 24, 196, 178, 14, 151, 14, 219, 137, 7, 203, 115, 207, 24, 185]), 
    iterations: 100000, 
    hash: "SHA-256",
};

// 1. Derivar la clave criptográfica a partir de la Clave Maestra
async function deriveKey(masterKey) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(masterKey),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        keyDerivationAlgorithm,
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// 2. Cifrado Seguro con AES-GCM (usado para guardar la captura)
async function encryptSecurely(text, masterKey) {
    if (!masterKey) throw new Error("Master Key no proporcionada para cifrar.");

    const derivedKey = await deriveKey(masterKey);
    const iv = crypto.getRandomValues(new Uint8Array(16)); // Vector de inicialización único
    
    const algo = { name: "AES-GCM", iv: iv, tagLength: 128 };

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


async function saveCredential(url, username, password) {
    const { masterKey } = await chrome.storage.local.get('masterKey');
    
    if (!masterKey) {
        console.error("No Master Key set. Cannot save credentials.");
        return { success: false, message: "Clave Maestra no establecida." };
    }

    const { vault = [] } = await chrome.storage.local.get('vault');
    
    try {
        // Cifrar antes de guardar usando la función segura
        const encryptedPassword = await encryptSecurely(password, masterKey);
        
        const newCredential = {
            id: Date.now(),
            url: url,
            username: username,
            password: encryptedPassword, // La contraseña cifrada
            savedAt: new Date().toISOString()
        };
        
        vault.push(newCredential);
        await chrome.storage.local.set({ vault: vault });
        return { success: true, message: "Credencial guardada con éxito." };
    } catch (e) {
        console.error("Fallo de cifrado:", e);
        return { success: false, message: "Fallo de cifrado. Asegúrate de que la Clave Maestra es válida." };
    }
}


// --- GESTIÓN DE EVENTOS Y MENSAJES (El resto del código permanece igual) ---

// 1. Inicialización del Menú Contextual (UX)
chrome.runtime.onInstalled.addListener(() => {
    // Crear opciones en el menú contextual (clic derecho)
    chrome.contextMenus.create({
        id: "generateAndFill",
        title: "Password Centinel: Generar y Rellenar Contraseña",
        contexts: ["editable"] // Solo aparece en campos de texto editables
    });
    chrome.contextMenus.create({
        id: "analyzeField",
        title: "Password Centinel: Analizar Contraseña",
        contexts: ["editable"]
    });
});

// 2. Listener para acciones del Menú Contextual (UX)
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab) return;
    
    // El content script se encargará de la acción
    if (info.menuItemId === "generateAndFill") {
        chrome.tabs.sendMessage(tab.id, { 
            action: "contextMenuGenerate", 
            targetElementId: info.targetElementId
        });
    } else if (info.menuItemId === "analyzeField") {
        chrome.tabs.sendMessage(tab.id, { 
            action: "contextMenuAnalyze", 
            targetElementId: info.targetElementId
        });
    }
});

// 3. Listener principal para mensajes
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // a) Análisis de Brechas (HIBP)
    if (request.action === 'checkBreach') {
        const password = request.password;
        // Simulación de HIBP (Mantener simulación simple por ahora)
        if (password.includes('123456') || password.includes('password') || password.includes('qwerty')) {
            sendResponse({ breached: true, count: 10000 });
        } else {
            sendResponse({ breached: false, count: 0 });
        }
        return true; 
    }

    // b) Captura y Guardado de Credenciales (Alto Impacto)
    if (request.action === 'captureAndSave') {
        const { url, username, password } = request;
        
        // Ejecutar la función asíncrona de guardado seguro
        saveCredential(url, username, password).then(result => {
            sendResponse(result);
        });
        return true; // Respuesta asíncrona
    }
});

// 4. Listener para la navegación de la página o actualización de la pestaña 
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Asegurarse de que el content script se ejecute para el análisis de campos
        chrome.tabs.sendMessage(tabId, { action: "pageLoaded" }).catch(() => {});
    }
});