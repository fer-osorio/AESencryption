#ifndef _INCLUDED_AESENCRYPTION_
#define _INCLUDED_AESENCRYPTION_

#include<iostream>
#include<stdint.h>

#define BLOCK_SIZE 16

namespace AESencryption {

struct InitVector{
	uint8_t data[BLOCK_SIZE];
};

struct Key;									// -Declaring struct Key and class Cipher to use them as arguments in functions
class Cipher;
std::ostream& operator << (std::ostream& ost, Key k);
std::ostream& operator << (std::ostream& st, const Cipher& c);			// -Declaration here so this function is inside the name space function.

struct Key {
public:
	enum struct Len {_128 = 128,_192 = 192,_256 = 256};			// -Allowed AES key lengths
	enum struct OpMode {
		ECB,								// -Electronic Code Book (not recommended).
		CBC,								// -Cipher Block Chaining.
	};
private:
	uint8_t*data = NULL;
	Len	lenBits;							// -Length in bits.
	size_t	lenBytes;							// -Length in bytes.
	OpMode	opMode_;
	bool initializedIV  = false;						// -Tells if the initial vector is already initialized or not
	InitVector IV = {							// -Initial vector for the CBC operation mode
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0
	};

	friend Cipher;
	// The following two private constructors can only be acceced by Cipher class, the intention is to have well-constructed keys for the user.
	Key();
	Key(Len, OpMode);
	Key(const uint8_t* const _key, Len, OpMode);
public:
	Key(const char*const fname);						// -Building from binary file.
	Key(const Key&);
	~Key();

	Key& operator =  (const Key&);
	bool operator == (const Key&) const;
	friend std::ostream& operator << (std::ostream& ost, Key k);

	OpMode getOpMode() const{ return this->opMode_; }
	size_t getLenBytes() const {return this->lenBytes;}

	void save(const char*const fname) const;				// -Saving information in a binary file.
private:
	void set_IV(const InitVector source);					// -Sets initial vector by copying the array passed as argument
	bool IVisInitialized() const { return this->initializedIV; }
	void write_IV(uint8_t*const destination) const {			// -Writes IV in destination
		for(int i = 0; i < BLOCK_SIZE; i++) destination[i] = this->IV.data[i]; // -Warning: We are supposing we have at least 16 bytes of space in destination
	}
	void write_Key(uint8_t*const destination) const {			// -Writes key in destination. Warning: We're supposing we have enough space in
		for(size_t i = 0; i < this->lenBytes; i++) destination[i] = this->data[i]; //  destination array.
	}
};

class Cipher {
private:
	// -The default values for a cipher object are the values for a key of 256 bits
	Key key = Key();
	int Nk = 8, Nr = 14, keyExpLen = 240;
	uint8_t* keyExpansion = NULL;
public:
	Cipher();								// -The default constructor will set the key expansion as zero in every element.
	Cipher(const Key&);
	Cipher(const Cipher& a);
	~Cipher();

	Cipher& operator = (const Cipher& a);
	friend std::ostream& operator << (std::ostream& st, const Cipher& c);

	void encrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;	// -Encrypts using operation mode stored in Key object
	void decrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;	// -Decrypts using operation mode stored in Key object

	void saveKey(const char*const fname) const{ this->key.save(fname); }
	Key::OpMode getOpMode() const{ return this->key.getOpMode(); }

	private:
	void buildKeyExpansion();						// -Creates key expansion
	void formInitialVector();						// -Creates initial vector and writes it on destination array
};
};
#endif