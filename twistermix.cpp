#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <bitset>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <sstream>
using namespace std;

//XOR byte a byte entre bloque y subclave
vector<uint8_t> xorBlock(const vector<uint8_t>& block, const vector<uint8_t>& key) {
    vector<uint8_t> out(4);
    for (int i = 0; i < 4; i++) out[i] = block[i] ^ key[i];
    return out;
}

// Rotar bits a la izquierda n posiciones en cada byte
vector<uint8_t> rotlBytes(const vector<uint8_t>& block, int n) {
    vector<uint8_t> out(4);
    for (int i = 0; i < 4; i++)
        out[i] = (uint8_t)((block[i] << n) | (block[i] >> (8 - n)));
    return out;
}

// Rotar bits a la derecha (para descifrar)
vector<uint8_t> rotrBytes(const vector<uint8_t>& block, int n) {
    vector<uint8_t> out(4);
    for (int i = 0; i < 4; i++)
        out[i] = (uint8_t)((block[i] >> n) | (block[i] << (8 - n)));
    return out;
}

// Intercambiar bytes pares ↔ impares
vector<uint8_t> swapPairs(const vector<uint8_t>& block) {
    vector<uint8_t> out = block;
    swap(out[0], out[1]);
    swap(out[2], out[3]);
    return out;
}

// S-box
vector<uint8_t> sbox(const vector<uint8_t>& block) {
    vector<uint8_t> out(4);
    for (int i = 0; i < 4; i++) {
        // Operación reversible XOR con patrón y rotación
        out[i] = (block[i] ^ 0xAA);  // Confusión
        out[i] = (uint8_t)((out[i] << 1) | (out[i] >> 7));  // Rotación izquierda 1 bit
    }
    return out;
}

// S-box inversa
vector<uint8_t> inv_sbox(const vector<uint8_t>& block) {
    vector<uint8_t> out(4);
    for (int i = 0; i < 4; i++) {
        // Inverso de la operación anterior
        out[i] = (uint8_t)((block[i] >> 1) | (block[i] << 7));  // Rotación derecha 1 bit
        out[i] = out[i] ^ 0xAA;  // XOR con el mismo patrón
    }
    return out;
}

// Generar subclaves 
vector<vector<uint8_t>> genSubkeys(const vector<uint8_t>& key) {
    vector<vector<uint8_t>> subkeys;
    vector<uint8_t> temp = key;
    
    for (int r = 0; r < 8; r++) {
        // Crear subclave única para cada ronda
        vector<uint8_t> subkey(4);
        for (int i = 0; i < 4; i++) {
            subkey[i] = temp[i] ^ (r * 17 + i * 3);  // Mezcla con constante única
            subkey[i] = (uint8_t)((subkey[i] << (r % 7 + 1)) | (subkey[i] >> (8 - (r % 7 + 1))));  // Rotación variable
        }
        subkeys.push_back(subkey);
        
        // Rotación circular de bytes para siguiente ronda
        vector<uint8_t> rot = {temp[1], temp[2], temp[3], temp[0]};
        temp = rot;
    }
    return subkeys;
}

// Mostrar bloque en hexadecimal
void printHex(const vector<uint8_t>& block) {
    for (auto b : block)
        cout << hex << setw(2) << setfill('0') << (int)b;
    cout << dec;
}

// Convertir hexadecimal string a vector de bytes
vector<uint8_t> hexStringToBytes(const string& hexStr) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string byteString = hexStr.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Convertir vector de bytes a string hexadecimal
string bytesToHexString(const vector<uint8_t>& bytes) {
    stringstream ss;
    for (auto b : bytes) {
        ss << hex << setw(2) << setfill('0') << (int)b;
    }
    return ss.str();
}

// Función para derivar clave de 4 bytes desde cualquier longitud
vector<uint8_t> deriveKey(const vector<uint8_t>& inputKey) {
    vector<uint8_t> derivedKey(4, 0);
    
    if (inputKey.empty()) return derivedKey;
    
    // Mezclar todos los bytes de la clave original en 4 bytes
    for (size_t i = 0; i < inputKey.size(); i++) {
        derivedKey[i % 4] ^= inputKey[i];
    }
    
    // Añadir más variación
    for (int i = 0; i < 4; i++) {
        derivedKey[i] = (uint8_t)((derivedKey[i] << 3) | (derivedKey[i] >> 5));
        derivedKey[i] ^= (inputKey.size() & 0xFF);
    }
    
    return derivedKey;
}

// Cifrado de un bloque
vector<uint8_t> encryptBlock(vector<uint8_t> block, const vector<uint8_t>& key) {
    auto subkeys = genSubkeys(key);
    for (int r = 0; r < 8; r++) {
        block = xorBlock(block, subkeys[r]);  // Confusión
        block = sbox(block);                  // Confusión
        block = rotlBytes(block, 3);          // Difusión (rotación)
        block = swapPairs(block);             // Difusión (transposición)
    }
    return block;
}

// Orden inverso
vector<uint8_t> decryptBlock(vector<uint8_t> block, const vector<uint8_t>& key) {
    auto subkeys = genSubkeys(key);
    for (int r = 7; r >= 0; r--) {
        block = swapPairs(block);             // Inverso de transposición
        block = rotrBytes(block, 3);          // Inverso de rotación
        block = inv_sbox(block);              // Inverso de S-box
        block = xorBlock(block, subkeys[r]);  // Inverso de XOR
    }
    return block;
}

// Padding
void pad(vector<uint8_t>& data) {
    size_t padLen = 4 - (data.size() % 4);
    if (padLen == 0) padLen = 4;
    for (size_t i = 0; i < padLen; i++)
        data.push_back((uint8_t)padLen);
}

// Quitar padding
void unpad(vector<uint8_t>& data) {
    if (data.empty()) return;
    uint8_t padVal = data.back();
    if (padVal == 0 || padVal > 4) return;
    
    // Verificar que todos los bytes de padding sean correctos
    bool valid = true;
    for (int i = 0; i < padVal; i++) {
        if (data[data.size() - 1 - i] != padVal) {
            valid = false;
            break;
        }
    }
    
    if (valid) {
        data.resize(data.size() - padVal);
    }
}

// Cifrar mensaje completo
vector<uint8_t> encryptMessage(const vector<uint8_t>& plaintext, const vector<uint8_t>& key) {
    vector<uint8_t> data = plaintext;
    pad(data);

    vector<uint8_t> ciphertext;
    for (size_t i = 0; i < data.size(); i += 4) {
        vector<uint8_t> block(data.begin() + i, data.begin() + i + 4);
        auto encrypted = encryptBlock(block, key);
        ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
    }
    return ciphertext;
}

// Descifrar mensaje completo
vector<uint8_t> decryptMessage(const vector<uint8_t>& ciphertext, const vector<uint8_t>& key) {
    vector<uint8_t> plaintext;
    for (size_t i = 0; i < ciphertext.size(); i += 4) {
        vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + 4);
        auto decrypted = decryptBlock(block, key);
        plaintext.insert(plaintext.end(), decrypted.begin(), decrypted.end());
    }
    unpad(plaintext);
    return plaintext;
}

// Función para mostrar el menú
void showMenu() {
    cout << "TWISTERMIX" << endl;
    cout << "1. Encrypt text" << endl;
    cout << "2. Decrypt text" << endl;
    cout << "3. Exit" << endl;
    cout << "Select an option: ";
}


int main() {
    int option;
    
    while (true) {
        showMenu();
        cin >> option;
        cin.ignore(); // Limpiar el buffer
        
        if (option == 3) {
            cout << "See ya!!! :D" << endl;
            break;
        }
        
        string text, keyStr;
        
        if (option == 1) {
            // MODO CIFRADO
            cout << "\nEncryption mode" << endl;
            cout << "Text to encrypt (100 characters): ";
            getline(cin, text);
            if (text.size() > 100) text.resize(100);

            cout << "Key: ";
            getline(cin, keyStr);

            // Convertir texto y clave a bytes, luego derivar clave a 4 bytes
            vector<uint8_t> plaintext(text.begin(), text.end());
            vector<uint8_t> inputKey(keyStr.begin(), keyStr.end());
            vector<uint8_t> key = deriveKey(inputKey);

            // Cifrar todo el mensaje
            auto cipher = encryptMessage(plaintext, key);
            cout << "\nEncrypted text (hex): " << bytesToHexString(cipher) << endl;
            
            
        } else if (option == 2) {
            // MODO DESCIFRADO
            cout << "\nDecrypt mode =)" << endl;
            cout << "Encrypted text (hex): ";
            getline(cin, text);
            
            // Eliminar espacios si los hay
            text.erase(remove_if(text.begin(), text.end(), ::isspace), text.end());

            cout << "Key: ";
            getline(cin, keyStr);

            // Convertir hexadecimal a bytes y derivar clave a 4 bytes
            vector<uint8_t> ciphertext = hexStringToBytes(text);
            vector<uint8_t> inputKey(keyStr.begin(), keyStr.end());
            vector<uint8_t> key = deriveKey(inputKey);

            // Descifrar todo el mensaje
            auto plain = decryptMessage(ciphertext, key);

            cout << "\nDecrypted text: ";
            for (auto c : plain) {
                if (isprint(c)) cout << (char)c;
                else cout << "?"; // Caracteres no imprimibles
            }
            cout << endl;
            
        } else {
            cout << "Invalid option" << endl;
        }
        
        cout << endl; // Línea en blanco para separar operaciones
    }

    return 0;
}