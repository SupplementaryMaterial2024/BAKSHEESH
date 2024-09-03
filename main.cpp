#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

int Sbox[16] = {0x3, 0x0, 0x6, 0xD, 0xB, 0x5, 0x8, 0xE, 0xC, 0xF, 0x9, 0x2, 0x4, 0xA, 0x7, 0x1};

int RoundConstant[35] = {2, 33, 16, 9, 36, 19, 40, 53, 26, 13, 38, 51, 56, 61, 62, 31, 14, 7, 34, 49, 24, 45, 54, 59, 28, 47, 22, 43, 20, 11, 4, 3, 32, 17, 8};

int BitPermutation[128] = {96, 65, 34, 3, 64, 33, 2, 99, 32, 1, 98, 67, 0, 97, 66, 35, 100, 69, 38, 7, 68, 37, 6, 103, 36, 5, 102, 71, 4, 101, 70, 39, 104, 73, 42, 11, 72, 41, 10, 107, 40, 9, 106, 75, 8, 105, 74, 43, 108, 77, 46, 15, 76, 45, 14, 111, 44, 13, 110, 79, 12, 109, 78, 47, 112, 81, 50, 19, 80, 49, 18, 115, 48, 17, 114, 83, 16, 113, 82, 51, 116, 85, 54, 23, 84, 53, 22, 119, 52, 21, 118, 87, 20, 117, 86, 55, 120, 89, 58, 27, 88, 57, 26, 123, 56, 25, 122, 91, 24, 121, 90, 59, 124, 93, 62, 31, 92, 61, 30, 127, 60, 29, 126, 95, 28, 125, 94, 63};

void KeySchedule(int Key[8], int SubKey[36][8])
{
    for (int group = 0; group < 8; group++)
    {
        SubKey[0][group] = Key[group];
    }
    for (int round = 1; round < 36; round++)
    {
        int X[32];
        for (int group = 0; group < 8; group++)
        {
            for (int sbox = 0; sbox < 4; sbox++)
            {
                X[4 * group + sbox] = ((SubKey[round - 1][group] >> (4 * (3 - sbox))) & (0xf));
            }
        }
        int temp[128];
        for (int sbox = 0; sbox < 32; sbox++)
        {
            for (int bit = 0; bit < 4; bit++)
            {
                temp[4 * sbox + bit] = ((X[sbox] >> bit) & (0x1));
            }
        }
        
        int buf[128];
        for (int i = 0; i < 127; i++)
        {
            buf[i] = temp[i + 1];
        }
        buf[127] = temp[0];
        
        for (int sbox = 0; sbox < 32; sbox++)
        {
            X[sbox] = 0;
            for (int bit = 0; bit < 4; bit++)
            {
                X[sbox] ^= (buf[4 * sbox + bit] << bit);
            }
        }
        
        for (int group = 0; group < 8; group++)
        {
            SubKey[round][group] = 0;
            for (int sbox = 0; sbox < 4; sbox++)
            {
                SubKey[round][group] ^= (X[4 * group + sbox] << (4 * (3 - sbox)));
            }
        }
    }
}

void BAKSHEESH_Enc(int Plaintext[8], int SubKey[36][8], int Ciphertext[8])
{
    int X[8];
    for (int group = 0; group < 8; group++)
    {
        X[group] = Plaintext[group];
    }
    for (int round = 0; round < 35; round++)
    {
        for (int group = 0; group < 8; group++)
        {
            X[group] ^= SubKey[round][group];
        }
        int Y[32];
        for (int group = 0; group < 8; group++)
        {
            for (int sbox = 0; sbox < 4; sbox++)
            {
                Y[4 * group + sbox] = Sbox[(X[group] >> (4 * (3 - sbox))) & (0xf)];
            }
        }
        
        int InState[128];
        for (int sbox = 0; sbox < 32; sbox++)
        {
            for (int bit = 0; bit < 4; bit++)
            {
                InState[4 * sbox + bit] = ((Y[sbox] >> (3 - bit)) & (0x1));
            }
        }
        
        int OutState[128];
        for (int bit = 0; bit < 128; bit++)
        {
            OutState[BitPermutation[bit]] = InState[bit];
        }
        
        for (int sbox = 0; sbox < 32; sbox++)
        {
            Y[sbox] = 0;
            for (int bit = 0; bit < 4; bit++)
            {
                Y[sbox] ^= (OutState[4 * sbox + bit] << (3 - bit));
            }
        }
        
        OutState[11] ^= ((RoundConstant[round] >> 0) & (0x1));
        OutState[14] ^= ((RoundConstant[round] >> 1) & (0x1));
        OutState[16] ^= ((RoundConstant[round] >> 2) & (0x1));
        OutState[32] ^= ((RoundConstant[round] >> 3) & (0x1));
        OutState[64] ^= ((RoundConstant[round] >> 4) & (0x1));
        OutState[105] ^= ((RoundConstant[round] >> 5) & (0x1));
        
        for (int group = 0; group < 8; group++)
        {
            X[group] = 0;
            for (int bit = 0; bit < 16; bit++)
            {
                X[group] ^= (OutState[16 * group + bit] << (15 - bit));
            }
        }
    }
    
    for (int group = 0; group < 8; group++)
    {
        X[group] ^= SubKey[35][group];
    }
    
    for (int group = 0; group < 8; group++)
    {
        Ciphertext[group] = 0;
        for (int sbox = 0; sbox < 4; sbox++)
        {
            Ciphertext[group] ^= (((X[7 - group] >> (4 * sbox)) & (0xf)) << (4 * (3 - sbox)));
        }
    }
}

int main()
{
    int PreKey[8] = {0x5920, 0xeffb, 0x52bc, 0x61e3, 0x3a98, 0x4253, 0x21e7, 0x6915};
    int PrePlaintext[8] = {0xe651, 0x7531, 0xabf6, 0x3f3d, 0x7805, 0xe126, 0x943a, 0x081c};
    
    int Plaintext[8];
    int Key[8];
    for (int group = 0; group < 8; group++)
    {
        Plaintext[group] = 0;
        Key[group] = 0;
        for (int sbox = 0; sbox < 4; sbox++)
        {
            Plaintext[group] ^= (((PrePlaintext[7 - group] >> (4 * (3 - sbox))) & (0xf)) << (4 * sbox));
            Key[group] ^= (((PreKey[7 - group] >> (4 * (3 - sbox))) & (0xf)) << (4 * sbox));
        }
    }
    
    int SubKey[36][8];
    int Ciphertext[8];
    
    KeySchedule(Key, SubKey);
    BAKSHEESH_Enc(Plaintext, SubKey, Ciphertext);
    
    for (int group = 0; group < 8; group++)
    {
        cout << (hex) << Ciphertext[group] << " ";
    }
    cout << endl;
    
    
    return 0;
}
