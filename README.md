# Password Centinel

**[Download on Chrome Web Store](https://chromewebstore.google.com/detail/fiephcocbhccfidlfnklglonoplmggcl)** | **[Live Website](https://passwdcentinel.eduolihez.com)**

Password Centinel is a privacy-focused, local-first Chrome extension designed to analyze, generate, and securely manage your passwords without ever leaving your browser. Built with uncompromising simplicity and military-grade security principles.

### Overview

This project provides a comprehensive security suite directly within your browser. Unlike cloud-based password managers, Password Centinel operates on a strict "Local-First" architecture, ensuring your encrypted vault and analysis data never touch an external server. 

### Key Features

* **Control Center & Vault:** Securely store your credentials in an encrypted local vault, locked behind a single Master Key. If the key is lost, the data remains inaccessible, ensuring absolute privacy.
* **Real-Time Analyzer:** Evaluates password strength and entropy locally via JavaScript as you type.
* **Anti-Breach Detection (HIBP):** Verifies if your passwords have been exposed in known data breaches using the Have I Been Pwned API (via secure k-anonymity verification).
* **Advanced Generator:** Create cryptographically secure passwords up to 64 characters long, with customizable rules for symbols, numbers, and casing.
* **Health Dashboard:** Get an instant overview of your security posture, including counts of compromised, reused, and weak passwords.

### Tech Stack

* **Platform:** Chrome Extensions API (Manifest V3)
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (ES6+)
* **Security:** Local-first cryptography, HIBP integration
* **Architecture:** Zero dependencies, no heavy frameworks

### Local Setup

To run this extension locally for development or auditing:

1. Clone the repository:
   ```bash
   git clone [https://github.com/eduolihez/password-centinel.git](https://github.com/eduolihez/password-centinel.git)
    ```

2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the `extension` folder from the cloned repository.
5. The Password Centinel icon will appear in your browser toolbar.

### Contact

Eduardo — [eduolihez@gmail.com](mailto:eduolihez@gmail.com) · [LinkedIn](https://www.linkedin.com/in/eduolihez)