#include "pch.h"
#include "decrypt.h"
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_free_ptr = std::unique_ptr<EVP_MD, decltype(&::EVP_MD_meth_free)>;

#include <atlenc.h>

static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;

void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);
void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);

secure_string DecodeBase64(LPCSTR lpszIn)
{
    secure_string sOut;
    int len = 0;

    int srclen = (int)strlen(lpszIn);
    ATL::Base64Decode(lpszIn, srclen, NULL, &len);

    if (len > 0)
    {
        sOut.resize(len);
        ATL::Base64Decode(lpszIn, srclen, (BYTE*)&sOut.front(), &len);
    }
    return sOut;
}

secure_string EncodeBase64(secure_string sIn)
{
    int srclen = (int)sIn.length();
    secure_string sOut;
    int len = Base64EncodeGetRequiredLength(srclen);

    if (len > 0)
    {
        sOut.resize(len);
        ATL::Base64Encode((const BYTE*) sIn.c_str(), srclen, &sOut.front(), &len);
    }
    return sOut;
}

void digest_key(std::string skey, std::string salt, byte hash[SHA256_DIGEST_LENGTH])
{
    memset(hash, 0, sizeof(hash));
    PKCS5_PBKDF2_HMAC(skey.c_str(), (int) skey.length(), (const unsigned char*)salt.c_str(), 
        (int) salt.length(), 10000, EVP_sha256(), SHA256_DIGEST_LENGTH, hash);
}

void InitSSL()
{
    static bool bInitted = false;
    if (!bInitted)
    {
        EVP_add_cipher(EVP_aes_256_cbc());
        bInitted = true;
    }
}

secure_string RubyDecode(std::string data, std::string salt, std::string iv, std::string key)
{
    if (iv.length() != BLOCK_SIZE)
        return secure_string();

    InitSSL();

    byte hash[KEY_SIZE];
    digest_key(key, salt, hash);

    secure_string rtext;
    secure_string ctext = DecodeBase64(data.c_str());

    byte iv_block[BLOCK_SIZE];
    memcpy_s(iv_block, sizeof(iv_block), iv.c_str(), iv.length());
    aes_decrypt(hash, iv_block, ctext, rtext);

    OPENSSL_cleanse(hash, sizeof(hash));

    return rtext;
}

secure_string RubyEncode(secure_string data, std::string salt, std::string iv, std::string key)
{
    if (iv.length() != BLOCK_SIZE)
        return secure_string();

    InitSSL();

    byte hash[KEY_SIZE];
    digest_key(key, salt, hash);

    byte iv_block[BLOCK_SIZE];
    memcpy_s(iv_block, sizeof(iv_block), iv.c_str(), iv.length());

    secure_string rtext;
    aes_encrypt(hash, iv_block, data, rtext);

    return EncodeBase64(rtext);
}

void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    // Recovered text contracts upto BLOCK_SIZE
    rtext.resize(ctext.size());
    int out_len1 = (int)rtext.size();

    rc = EVP_DecryptUpdate(ctx.get(), (byte*)&rtext[0], &out_len1, (const byte*)&ctext[0], (int)ctext.size());
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = (int)rtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0] + out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    rtext.resize(out_len1 + out_len2);
}

void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    // Recovered text expands upto BLOCK_SIZE
    ctext.resize(ptext.size() + BLOCK_SIZE);
    int out_len1 = (int)ctext.size();

    rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ctext[0], &out_len1, (const byte*)&ptext[0], (int)ptext.size());
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0] + out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Set cipher text size now that we know it
    ctext.resize(out_len1 + out_len2);
}
