// Password Sentinel - Logic v2.0

document.addEventListener('DOMContentLoaded', function() {
    initInteractiveTools();
    initSmoothScroll();
});

function initInteractiveTools() {
    // --- Tabs Logic (Control Center) ---
    const tabs = document.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.tool-panel');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Deactivate all
            tabs.forEach(t => t.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            
            // Activate selected
            tab.classList.add('active');
            const targetId = tab.dataset.tool + '-content';
            document.getElementById(targetId).classList.add('active');
        });
    });

    // --- 1. Analyzer Logic ---
    const passwordInput = document.getElementById('webPasswordInput');
    
    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            const password = e.target.value;
            if (password) {
                const analysis = analyzePassword(password);
                updateAnalyzerUI(analysis);
            } else {
                resetAnalyzerUI();
            }
        });
    }

    // --- 2. Generator Logic ---
    const generateBtn = document.getElementById('webGeneratePassword');
    const copyBtn = document.getElementById('webCopyPassword');
    const lengthRange = document.getElementById('webLengthRange');
    const lengthValue = document.getElementById('webLengthValue');

    // Update slider value
    if (lengthRange) {
        lengthRange.addEventListener('input', (e) => {
            lengthValue.textContent = e.target.value;
        });
    }

    // Generate Button
    if (generateBtn) {
        generateBtn.addEventListener('click', generateNewPassword);
        // Generate one on load
        generateNewPassword(); 
    }

    // Copy Button
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const passwordText = document.getElementById('webGeneratedPassword').textContent.trim();
            if (passwordText && passwordText !== "...") {
                navigator.clipboard.writeText(passwordText).then(() => {
                    const originalText = copyBtn.textContent;
                    copyBtn.textContent = "Copied!";
                    copyBtn.classList.add('btn-primary');
                    copyBtn.classList.remove('btn-secondary');
                    
                    setTimeout(() => {
                        copyBtn.textContent = originalText;
                        copyBtn.classList.remove('btn-primary');
                        copyBtn.classList.add('btn-secondary');
                    }, 2000);
                });
            }
        });
    }
}

// --- Helper Functions ---

function analyzePassword(password) {
    let score = 0;
    const length = password.length;
    
    // Basic Rules
    if (length >= 8) score += 1;
    if (length >= 12) score += 2;
    if (length >= 16) score += 1;
    
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNum = /[0-9]/.test(password);
    const hasSym = /[^A-Za-z0-9]/.test(password);
    
    if (hasUpper && hasLower) score += 1;
    if (hasNum) score += 1;
    if (hasSym) score += 2;

    // Normalize score
    let strength = 'weak';
    let label = 'Weak';
    
    if (score >= 7) { strength = 'strong'; label = 'Very Strong'; }
    else if (score >= 4) { strength = 'medium'; label = 'Good'; }

    // Estimated Time Calculation (Simulated for demo)
    const times = ['Instant', '2 secs', '5 mins', '3 days', '5 years', '400 centuries', 'Billions of years'];
    const timeIndex = Math.min(Math.floor(score / 1.5), times.length - 1);

    return {
        strength,
        label,
        length,
        timeToCrack: times[timeIndex],
        complexity: hasSym ? 'High' : (hasNum ? 'Medium' : 'Low'),
        status: score >= 5 ? 'Secure' : 'Vulnerable'
    };
}

function updateAnalyzerUI(data) {
    const fill = document.getElementById('strengthFillWeb');
    const feedback = document.getElementById('webPasswordFeedback');
    
    // Bar
    fill.className = `meter-fill ${data.strength}`;
    fill.style.width = data.strength === 'strong' ? '100%' : (data.strength === 'medium' ? '60%' : '30%');
    
    // Text
    feedback.innerHTML = `Level: <strong>${data.label}</strong>`;
    
    // Stats
    document.getElementById('webLengthStat').textContent = data.length;
    document.getElementById('webTimeToCrackStat').textContent = data.timeToCrack;
    document.getElementById('webSymbolStat').textContent = data.complexity;
    document.getElementById('webStatusStat').textContent = data.status;
    
    // Color status
    const statusEl = document.getElementById('webStatusStat');
    statusEl.style.color = data.status === 'Secure' ? 'var(--success)' : 'var(--danger)';
}

function resetAnalyzerUI() {
    document.getElementById('strengthFillWeb').style.width = '0%';
    document.getElementById('webPasswordFeedback').textContent = 'Start typing...';
    document.getElementById('webLengthStat').textContent = '0';
    document.getElementById('webTimeToCrackStat').textContent = '-';
    document.getElementById('webSymbolStat').textContent = '-';
    document.getElementById('webStatusStat').textContent = '-';
}

function generateNewPassword() {
    const length = parseInt(document.getElementById('webLengthRange').value);
    const useUpper = document.getElementById('webUseUppercase').checked;
    const useLower = document.getElementById('webUseLowercase').checked;
    const useNum = document.getElementById('webUseNumbers').checked;
    const useSym = document.getElementById('webUseSymbols').checked;

    const chars = {
        upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lower: 'abcdefghijklmnopqrstuvwxyz',
        num: '0123456789',
        sym: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };

    let charset = '';
    if (useUpper) charset += chars.upper;
    if (useLower) charset += chars.lower;
    if (useNum) charset += chars.num;
    if (useSym) charset += chars.sym;

    if (!charset) {
        document.getElementById('webGeneratedPassword').textContent = "Select options";
        return;
    }

    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    document.getElementById('webGeneratedPassword').textContent = password;
}

function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const headerOffset = 100;
                const elementPosition = target.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: "smooth"
                });
            }
        });
    });
}