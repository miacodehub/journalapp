#include <iostream>
#include <string>

class PasswordEntry {
private:
    std::string account;
    std::string username;
    std::string password;
    std::string lastSetDate;

public:
    // Constructor
    PasswordEntry(std::string acc, std::string user, std::string pass, std::string date) 
        : account(acc), username(user), password(pass), lastSetDate(date) {}

    // Getters
    std::string getAccount() const { return account; }
    std::string getUsername() const { return username; }
    std::string getPassword() const { return password; }
    std::string getLastSetDate() const { return lastSetDate; }
};

// Simple AES encryption function
std::string encrypt(const std::string& text, int shift) {
    std::string result = "";
    for (char c : text) {
        if (isalpha(c)) {
            char shifted = c + shift;
            if (!isalpha(shifted)) {
                shifted -= 26;  // Wrap around
            }
            result += shifted;
        } else {
            result += c;  // Non-alphabetic characters remain unchanged
        }
    }
    return result;
}

// Simple Caesar cipher decryption function
std::string decrypt(const std::string& text, int shift) {
    return encrypt(text, -shift);  // Decrypting is just encrypting with negative shift
}

int main() {
    // Example usage
    PasswordEntry entry("example.com", "user123", "password123", "2024-03-28");

    // Encrypt password
    std::string encryptedPassword = encrypt(entry.getPassword(), 3);
    std::cout << "Encrypted Password: " << encryptedPassword << std::endl;

    // Decrypt password
    std::string decryptedPassword = decrypt(encryptedPassword, 3);
    std::cout << "Decrypted Password: " << decryptedPassword << std::endl;

    return 0;
}
