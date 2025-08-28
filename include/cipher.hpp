#ifndef CIPHER_HPP
#define CIPHER_HPP

#include"key.hpp"
#include"encryptor.hpp"

namespace AESencryption {

std::ostream& operator << (std::ostream& st, const Cipher& c);			// -Declaration here so this function is inside the name space function.

class Cipher : public Encryptor {
private:
	// -The default values for a cipher object are the values for a key of 128 bits
	Key key = Key();
	size_t Nk = AESconstants::Nk128;
	size_t Nr = AESconstants::Nr128;
	size_t keyExpansionLength = AESconstants::keyExpansionLength128;
	uint8_t* keyExpansion = NULL;
public:
	Cipher();								// -The default constructor will set the key expansion as zero in every element.
	Cipher(const Key&);
	Cipher(const Cipher& a);
	~Cipher();

	Cipher& operator = (const Cipher& a);
	friend std::ostream& operator << (std::ostream& st, const Cipher& c);

	void encryption(std::vector<uint8_t>& data) const override;
	void decryption(std::vector<uint8_t>& data) const override;

	void saveKey(const char*const fname) const{ this->key.save(fname); }
	Key::OpMode getOpMode() const{ return this->key.getOpMode(); }

	private:
	void buildKeyExpansion();						// -Creates key expansion
	void formInitialVector();						// -Creates initial vector and writes it on destination array
	void encrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;	// -Encrypts using operation mode stored in Key object
	void decrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;	// -Decrypts using operation mode stored in Key object
};
};
#endif