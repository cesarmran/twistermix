// ==================== TWISTERMIX ALGORITHM IMPLEMENTATION ====================

// XOR byte a byte entre bloque y subclave
function xorBlock(block, key) {
    let out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) out[i] = block[i] ^ key[i];
    return out;
}

// Rotar bits a la izquierda n posiciones en cada byte
function rotlBytes(block, n) {
    let out = new Uint8Array(4);
    for (let i = 0; i < 4; i++)
        out[i] = (block[i] << n) | (block[i] >> (8 - n));
    return out;
}

// Rotar bits a la derecha (para descifrar)
function rotrBytes(block, n) {
    let out = new Uint8Array(4);
    for (let i = 0; i < 4; i++)
        out[i] = (block[i] >> n) | (block[i] << (8 - n));
    return out;
}

// Intercambiar bytes pares ↔ impares
function swapPairs(block) {
    let out = new Uint8Array(block);
    [out[0], out[1]] = [out[1], out[0]];
    [out[2], out[3]] = [out[3], out[2]];
    return out;
}

// S-box
function sbox(block) {
    let out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        // Operación reversible XOR con patrón y rotación
        out[i] = (block[i] ^ 0xAA);  // Confusión
        out[i] = (out[i] << 1) | (out[i] >> 7);  // Rotación izquierda 1 bit
    }
    return out;
}

// S-box inversa
function inv_sbox(block) {
    let out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        // Inverso de la operación anterior
        out[i] = (block[i] >> 1) | (block[i] << 7);  // Rotación derecha 1 bit
        out[i] = out[i] ^ 0xAA;  // XOR con el mismo patrón
    }
    return out;
}

// Generar subclaves 
function genSubkeys(key) {
    let subkeys = [];
    let temp = new Uint8Array(key);
    
    for (let r = 0; r < 8; r++) {
        // Crear subclave única para cada ronda
        let subkey = new Uint8Array(4);
        for (let i = 0; i < 4; i++) {
            subkey[i] = temp[i] ^ (r * 17 + i * 3);  // Mezcla con constante única
            subkey[i] = (subkey[i] << (r % 7 + 1)) | (subkey[i] >> (8 - (r % 7 + 1)));  // Rotación variable
        }
        subkeys.push(subkey);
        
        // Rotación circular de bytes para siguiente ronda
        let rot = new Uint8Array([temp[1], temp[2], temp[3], temp[0]]);
        temp = rot;
    }
    return subkeys;
}

// Convertir hexadecimal string a vector de bytes
function hexStringToBytes(hexStr) {
    let bytes = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < hexStr.length; i += 2) {
        let byteString = hexStr.substr(i, 2);
        bytes[i/2] = parseInt(byteString, 16);
    }
    return bytes;
}

// Convertir vector de bytes a string hexadecimal
function bytesToHexString(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Función para derivar clave de 4 bytes desde cualquier longitud
function deriveKey(inputKey) {
    let derivedKey = new Uint8Array(4);
    
    if (inputKey.length === 0) return derivedKey;
    
    // Mezclar todos los bytes de la clave original en 4 bytes
    for (let i = 0; i < inputKey.length; i++) {
        derivedKey[i % 4] ^= inputKey[i];
    }
    
    // Añadir más variación
    for (let i = 0; i < 4; i++) {
        derivedKey[i] = (derivedKey[i] << 3) | (derivedKey[i] >> 5);
        derivedKey[i] ^= (inputKey.length & 0xFF);
    }
    
    return derivedKey;
}

// Cifrado de un bloque
function encryptBlock(block, key) {
    let subkeys = genSubkeys(key);
    for (let r = 0; r < 8; r++) {
        block = xorBlock(block, subkeys[r]);  // Confusión
        block = sbox(block);                  // Confusión
        block = rotlBytes(block, 3);          // Difusión (rotación)
        block = swapPairs(block);             // Difusión (transposición)
    }
    return block;
}

// Orden inverso
function decryptBlock(block, key) {
    let subkeys = genSubkeys(key);
    for (let r = 7; r >= 0; r--) {
        block = swapPairs(block);             // Inverso de transposición
        block = rotrBytes(block, 3);          // Inverso de rotación
        block = inv_sbox(block);              // Inverso de S-box
        block = xorBlock(block, subkeys[r]);  // Inverso de XOR
    }
    return block;
}

// Padding
function pad(data) {
    let padLen = 4 - (data.length % 4);
    if (padLen === 0) padLen = 4;
    for (let i = 0; i < padLen; i++)
        data.push(padLen);
    return data;
}

// Quitar padding
function unpad(data) {
    if (data.length === 0) return data;
    let padVal = data[data.length - 1];
    if (padVal === 0 || padVal > 4) return data;
    
    // Verificar que todos los bytes de padding sean correctos
    let valid = true;
    for (let i = 0; i < padVal; i++) {
        if (data[data.length - 1 - i] !== padVal) {
            valid = false;
            break;
        }
    }
    
    if (valid) {
        data = data.slice(0, data.length - padVal);
    }
    return data;
}

// Cifrar mensaje completo
function encryptMessage(plaintext, key) {
    let data = Array.from(plaintext);
    data = pad(data);

    let ciphertext = [];
    for (let i = 0; i < data.length; i += 4) {
        let block = new Uint8Array(data.slice(i, i + 4));
        let encrypted = encryptBlock(block, key);
        ciphertext.push(...encrypted);
    }
    return new Uint8Array(ciphertext);
}

// Descifrar mensaje completo
function decryptMessage(ciphertext, key) {
    let plaintext = [];
    for (let i = 0; i < ciphertext.length; i += 4) {
        let block = new Uint8Array(ciphertext.slice(i, i + 4));
        let decrypted = decryptBlock(block, key);
        plaintext.push(...decrypted);
    }
    plaintext = unpad(plaintext);
    return new Uint8Array(plaintext);
}

// ==================== UI INTERACTION ====================

document.addEventListener('DOMContentLoaded', function() {
    const modeBtns = document.querySelectorAll('.mode-btn');
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
    const encryptBtn = document.getElementById('encrypt-btn');
    const decryptBtn = document.getElementById('decrypt-btn');
    const plaintextInput = document.getElementById('plaintext');
    const charCount = document.getElementById('char-count');
    const encryptKeyInput = document.getElementById('encrypt-key');
    const ciphertextInput = document.getElementById('ciphertext');
    const decryptKeyInput = document.getElementById('decrypt-key');
    const resultContainer = document.getElementById('result-container');
    const resultTitle = document.getElementById('result-title');
    const resultContent = document.getElementById('result-content');
    const copyBtn = document.getElementById('copy-btn');

    // Mode switching
    modeBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const mode = this.getAttribute('data-mode');
            
            // Update active button
            modeBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Show appropriate form
            if (mode === 'encrypt') {
                encryptForm.style.display = 'block';
                decryptForm.style.display = 'none';
            } else {
                encryptForm.style.display = 'none';
                decryptForm.style.display = 'block';
            }
            
            // Hide previous results
            resultContainer.classList.remove('active');
        });
    });

    // Character counter for plaintext
    plaintextInput.addEventListener('input', function() {
        const count = this.value.length;
        charCount.textContent = count;
        
        if (count > 100) {
            this.value = this.value.substring(0, 100);
            charCount.textContent = 100;
            charCount.style.color = 'var(--danger)';
        } else {
            charCount.style.color = '';
        }
    });

    // Encrypt button handler
    encryptBtn.addEventListener('click', function() {
        const plaintext = plaintextInput.value;
        const keyStr = encryptKeyInput.value;
        
        if (!plaintext) {
            alert('Please enter text to encrypt');
            return;
        }
        
        if (!keyStr) {
            alert('Please enter an encryption key');
            return;
        }
        
        // Convert text and key to bytes
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const inputKey = new TextEncoder().encode(keyStr);
        const key = deriveKey(inputKey);
        
        // Encrypt the message
        const cipher = encryptMessage(plaintextBytes, key);
        const hexResult = bytesToHexString(cipher);
        
        // Display result
        resultTitle.innerHTML = '🔐 Encrypted Text (HEX)';
        resultContent.textContent = hexResult;
        resultContainer.classList.add('active');
        
        // Scroll to result
        resultContainer.scrollIntoView({ behavior: 'smooth' });
    });

    // Decrypt button handler
    decryptBtn.addEventListener('click', function() {
        const ciphertext = ciphertextInput.value.replace(/\s/g, '');
        const keyStr = decryptKeyInput.value;
        
        if (!ciphertext) {
            alert('Please enter ciphertext to decrypt');
            return;
        }
        
        if (!keyStr) {
            alert('Please enter a decryption key');
            return;
        }
        
        // Validate hex string length
        if (ciphertext.length % 8 !== 0) {
            alert('Error: Ciphertext must have a length that is a multiple of 8 hexadecimal characters');
            return;
        }
        
        try {
            // Convert hex to bytes and key to bytes
            const ciphertextBytes = hexStringToBytes(ciphertext);
            const inputKey = new TextEncoder().encode(keyStr);
            const key = deriveKey(inputKey);
            
            // Decrypt the message
            const plain = decryptMessage(ciphertextBytes, key);
            const textResult = new TextDecoder().decode(plain);
            
            // Display result
            resultTitle.innerHTML = '🔓 Decrypted Text';
            resultContent.textContent = textResult;
            resultContainer.classList.add('active');
            
            // Scroll to result
            resultContainer.scrollIntoView({ behavior: 'smooth' });
        } catch (e) {
            alert('Error during decryption: ' + e.message);
        }
    });

    // Copy to clipboard
    copyBtn.addEventListener('click', function() {
        const textToCopy = resultContent.textContent;
        navigator.clipboard.writeText(textToCopy).then(() => {
            // Visual feedback
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyBtn.textContent = originalText;
            }, 2000);
        });
    });
});