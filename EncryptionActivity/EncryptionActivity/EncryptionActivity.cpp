/**
 * File: EncryptionDecryption.cpp
 * Author: David Allen
 * Date: 10-01-2023
 * Version: 2.0 - Updated Header
 *
 * Description:
 * This C++ program demonstrates encryption and decryption of a text file using XOR cipher.
 * The program reads data from a file, encrypts it, saves the encrypted data to another file,
 * and then decrypts the encrypted data and saves it to yet another file.
 *
 * File Details:
 * - "EncryptionDecryption.cpp": Main file containing the program logic.
 *
 * Included Libraries:
 * - <iostream>: Input/output operations
 * - <fstream>: File input/output operations
 * - <iomanip>: Formatting of input/output
 * - <sstream>: String stream for parsing
 * - <ctime>: Date and time functions
 *
 * Functions:
 * - std::string encrypt_decrypt(const std::string& source, const std::string& key):
 *   XOR-based encryption and decryption function.
 * - std::string read_file(const std::string& filename): Reads data from a file.
 * - std::string get_student_name(const std::string& string_data):
 *   Extracts student name from the data read from the file.
 * - void save_data_file(const std::string& filename, const std::string& student_name,
 *   const std::string& key, const std::string& data): Saves data to a file.
 * - int main(): Main function containing program logic.
 */

#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <ctime>

std::string encrypt_decrypt(const std::string& source, const std::string& key)
{
    // get lengths now instead of calling the function every time.
    // this would have most likely been inlined by the compiler, but design for perfomance.
    const auto key_length = key.length();
    const auto source_length = source.length();

    // assert that our input data is good
    assert(key_length > 0);
    assert(source_length > 0);

    std::string output = source;

    // loop through the source string char by char
    for (size_t i = 0; i < source_length; ++i)
    {
        // TODO: student need to change the next line from output[i] = source[i]
        // transform each character based on an xor of the key modded constrained to key length using a mod
        // XOR each character of the source string with the corresponding character from the key
        output[i] = source[i] ^ key[i % key_length];
    }

    // our output length must equal our source length
    assert(output.length() == source_length);

    // return the transformed string
    return output;
}

std::string read_file(const std::string& filename)
{
    std::string file_text;
    std::ifstream file(filename);

    if (file.is_open())
    {
        // Read the file line by line and append it to the file_text string
        std::string line;
        while (std::getline(file, line))
        {
            file_text += line + '\n'; // Add newline character as it's stripped by getline
        }

        file.close();
    }
    else
    {
        std::cerr << "Error opening file: " << filename << std::endl;
    }

    return file_text;
}

std::string get_student_name(const std::string& string_data)
{
    std::string student_name;

    // find the first newline
    size_t pos = string_data.find('\n');
    // did we find a newline
    if (pos != std::string::npos)
    { // we did, so copy that substring as the student name
        student_name = string_data.substr(0, pos);
    }

    return student_name;
}

void save_data_file(const std::string& filename, const std::string& student_name, const std::string& key, const std::string& data)
{
    //  TODO: implement file saving
    //  file format
    //  Line 1: student name
    //  Line 2: timestamp (yyyy-mm-dd)
    //  Line 3: key used
    //  Line 4+: data
    std::ofstream file(filename);

    if (file.is_open())
    {
        // Save the data to the file in the specified format
        file << student_name << '\n';

        // Get the current timestamp
        std::time_t now = std::time(nullptr);
        char timestamp[11]; // "yyyy-mm-dd\0"
        std::tm time_info;
        localtime_s(&time_info, &now);
        std::strftime(timestamp, sizeof(timestamp), "%F", &time_info);
        file << timestamp << '\n';

        file << key << '\n';
        file << data;

        file.close();
    }
    else
    {
        std::cerr << "Error creating file: " << filename << std::endl;
    }
}

int main()
{
    std::cout << "Encryption Decryption Test!" << std::endl;

    const std::string file_name = "inputdatafile.txt";
    const std::string encrypted_file_name = "encrypteddatafile.txt";
    const std::string decrypted_file_name = "decrypteddatafile.txt";
    const std::string source_string = read_file(file_name);
    const std::string key = "password";

    // Get the student name from the data file
    const std::string student_name = get_student_name(source_string);

    // Encrypt sourceString with key
    const std::string encrypted_string = encrypt_decrypt(source_string, key);

    // Save encrypted_string to file
    save_data_file(encrypted_file_name, student_name, key, encrypted_string);

    // Decrypt encryptedString with key
    const std::string decrypted_string = encrypt_decrypt(encrypted_string, key);

    // Save decrypted_string to file
    save_data_file(decrypted_file_name, student_name, key, decrypted_string);

    std::cout << "Read File: " << file_name << " - Encrypted To: " << encrypted_file_name << " - Decrypted To: " << decrypted_file_name << std::endl;

    return 0;
}




