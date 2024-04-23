#include <iostream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string>

// Function to encrypt plaintext using AES
std::string encryptAES(const std::string& plaintext, const unsigned char* key) {
    // Initialize OpenSSL cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Set AES encryption mode
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    // Allocate memory for ciphertext
    std::string ciphertext(plaintext.size() + AES_BLOCK_SIZE, '\0');
    int len;
    
    // Perform AES encryption
    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                      reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    int ciphertext_len = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len);
    ciphertext_len += len;

    // Clean up OpenSSL context
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// Function to decrypt ciphertext using AES
std::string decryptAES(const std::string& ciphertext, const unsigned char* key) {
    // Initialize OpenSSL cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Set AES decryption mode
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    // Allocate memory for decrypted plaintext
    std::string plaintext(ciphertext.size(), '\0');
    int len;

    // Perform AES decryption
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                      reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    int plaintext_len = len;

    // Finalize decryption
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len);
    plaintext_len += len;

    // Clean up OpenSSL context
    EVP_CIPHER_CTX_free(ctx);

    // Remove padding if necessary
    if (plaintext_len < ciphertext.size()) {
        plaintext.resize(plaintext_len);
    }

    return plaintext;
}

int main() {
    // Example usage
    std::string plaintext;

    // Generate a random AES key (128 bits / 16 bytes)
    unsigned char aesKey[AES_BLOCK_SIZE];
    RAND_bytes(aesKey, AES_BLOCK_SIZE);
    std::cout << "enter string" << std::endl;
    std::cin>> plaintext;
    // Encrypt plaintext using AES
    std::string ciphertext = encryptAES(plaintext, aesKey);
    std::cout << "Encrypted Text: " << ciphertext << std::endl;
    std::cout << "you ready for decrypted text?" << std::endl;
    // Decrypt ciphertext using AES
    std::string decryptedText = decryptAES(ciphertext, aesKey);
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
