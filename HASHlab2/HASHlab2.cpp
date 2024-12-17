#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <iomanip>
#include <unordered_map>
#include <bitset>
#include <cstdint>
#include "include/lsh.h"

using namespace std;

//Auxiliary functions for working with hash function
bool compareHashes(const lsh_u8* hash1, const lsh_u8* hash2, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (hash1[31 - i] != hash2[31 - i]) {
            return false;
        }
    }
    return true;
}

//void computeHash(const string& message, lsh_u8* hashResult) {
//    lsh_u8* data = reinterpret_cast<lsh_u8*>(const_cast<char*>(message.c_str()));
//    lsh_digest(LSH_TYPE_256, data, message.size() * 8, hashResult);
//}

void computeHash(const lsh_u8* data, size_t length, lsh_u8* hashResult) {
    lsh_digest(LSH_TYPE_256, data, length * 8, hashResult);
}

void printHash(const lsh_u8* hash) {
    for (int i = 0; i < 32; i++) {
        std::cout << hex << setfill('0') << setw(2) << (int)hash[i];
    }
    std::cout << endl;
}

void printHash(const lsh_u8* hash, int bytes) {
    for (int i = 0; i < 32 - bytes; i++) {
        std::cout << hex << setfill('0') << setw(2) << (int)hash[i];
    }

    for (int i = 32 - bytes; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << "}" << endl;
}

uint32_t generate_random_32bit() {
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    return dist(rng);
}

uint16_t generate_random_16bit() {
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint16_t> dist(0, UINT16_MAX);
    return dist(rng);
}

void redundancy_function(const lsh_u8* x, const lsh_u8* r, lsh_u8* result) {
    memcpy(result, r, 14); // Copy redundancy prefix
    memcpy(result + 14, x, 2); // Copy x
}

unordered_map<uint16_t, uint16_t> build_table(size_t K, size_t L, const lsh_u8* r) {
    unordered_map<uint16_t, uint16_t> table;
    lsh_u8 hash[32];
    lsh_u8 buffer[16]; // For redundancy_function

    for (size_t i = 0; i < K; ++i) {
        uint16_t x0 = generate_random_16bit();
        uint16_t current = x0;

        for (size_t j = 0; j < L; ++j) {
            redundancy_function(reinterpret_cast<lsh_u8*>(&current), r, buffer);
            computeHash(buffer, 16, hash);
            current = *(reinterpret_cast<uint16_t*>(&hash[30]));
        }

        redundancy_function(reinterpret_cast<lsh_u8*>(&current), r, buffer);
        computeHash(buffer, 16, hash);
        uint16_t xL = *(reinterpret_cast<uint16_t*>(&hash[30]));
        table[xL] = x0;
    }


    return table;
}

string find_preimage(const lsh_u8* target_hash, const unordered_map<uint16_t, uint16_t>& table, size_t K, size_t L, const lsh_u8* r) {
    uint16_t y = *(reinterpret_cast<const uint16_t*>(&target_hash[30]));
    lsh_u8 hash[32];
    lsh_u8 buffer[16]; // For redundancy_function

    for (size_t j = 0; j < L; ++j) {
        auto it = table.find(y);
        if (it != table.end()) {
            uint16_t x = it->second;

            for (size_t m = 0; m < L - j; ++m) {
                redundancy_function(reinterpret_cast<lsh_u8*>(&x), r, buffer);
                computeHash(buffer, 16, hash);
                x = *(reinterpret_cast<uint16_t*>(&hash[30]));
            }

            redundancy_function(reinterpret_cast<lsh_u8*>(&x), r, buffer);
            computeHash(buffer, 16, hash);
            if (compareHashes(hash, target_hash, 2)) {

                //printHash(hash);
                //printHash(target_hash);

                return to_string(x);
            }
          
            /*else {
                return "Error: Preimage not found";
            }*/
        }

        redundancy_function(reinterpret_cast<lsh_u8*>(&y), r, buffer);
        computeHash(buffer, 16, hash);
        y = *(reinterpret_cast<uint16_t*>(&hash[30]));
    }

    return "Error: Preimage not found";
}

void generate_random_256bit_message(lsh_u8* message) {
    for (size_t i = 0; i < 32; ++i) {
        message[i] = static_cast<lsh_u8>(generate_random_32bit() & 0xFF);
    }
}

vector<unordered_map<uint16_t, uint16_t>> build_multiple_tables(size_t K, size_t L, size_t numTables, lsh_u8** rs){
    vector<unordered_map<uint16_t, uint16_t>> tables;
    for (size_t i = 0; i < numTables; ++i) {
        tables.push_back(build_table(K, L, rs[i]));
    }
    return tables;
}

int main() {
    vector<size_t> K_values = { 1 << 10, 1 << 12, 1 << 14 };
    vector<size_t> L_values = { 1 << 5, 1 << 6, 1 << 7 };
    size_t N = 10000; // Number of experiments

    // Part 1: Attack with a single precomputation table
    cout << "===== Part 1: Attack with a single precomputation table =====" << endl;
    for (size_t K : K_values) {
        for (size_t L : L_values) {
            lsh_u8 r[14];
            for (size_t i = 0; i < 14; ++i) {
                r[i] = static_cast<lsh_u8>(generate_random_32bit() & 0xFF);
            }

            auto table = build_table(K, L, r);
            size_t successful_searches = 0, failed_searches = 0;

            for (size_t experiment = 0; experiment < N; ++experiment) {
                lsh_u8 random_message[32];
                generate_random_256bit_message(random_message);
                lsh_u8 hash[32];
                computeHash(random_message, 32, hash);

                string preimage = find_preimage(hash, table, K, L, r);
                if (preimage != "Error: Preimage not found") {
                    ++successful_searches;
                }
                else {
                    ++failed_searches;
                }
            }

            double success_rate = (double)successful_searches / N * 100;
            cout << "K = " << K << ", L = " << L << ": ";
            cout << "Successful searches: " << success_rate << "%" << endl;
        }
    }

    // Part 2: Attack with multiple precomputation tables
    cout << "===== Part 2: Attack with multiple precomputation tables =====" << endl;
    for (size_t K : K_values) {
        for (size_t L : L_values) {
            
            size_t numTables = K; // Number of tables
            lsh_u8** rs = new lsh_u8* [numTables];
            
            for (int i = 0; i < K; i++) {
                lsh_u8* r = new lsh_u8[14];
                for (size_t j = 0; j < 14; ++j) {
                    r[j] = static_cast<lsh_u8>(generate_random_32bit() & 0xFF);
                }
                rs[i] = r;
            }

            auto tables = build_multiple_tables(K, L, numTables, rs);
            size_t successful_searches = 0, failed_searches = 0;

            for (size_t experiment = 0; experiment < N; ++experiment) {
                lsh_u8 random_message[32];
                generate_random_256bit_message(random_message);
                lsh_u8 hash[32];
                computeHash(random_message, 32, hash);

                bool found = false;
                for (int i = 0; i < numTables; i++) {
                    string preimage = find_preimage(hash, tables[i], K, L, rs[i]);
                    if (preimage != "Error: Preimage not found") {
                        found = true;
                        break;
                    }
                }

                if (found) {
                    ++successful_searches;
                }
                else {
                    ++failed_searches;
                }
            }

            double success_rate = (double)successful_searches / N * 100;
            cout << "K = " << K << ", L = " << L << ", Tables = " << numTables << ": ";
            cout << "Successful searches: " << success_rate << "%" << endl;
        }
    }

    return 0;
}
