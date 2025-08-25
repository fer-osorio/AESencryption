#ifndef KEY_HPP
#define KEY_HPP

#include"constants.hpp"
#include<iostream>
#include<stddef.h>
#include<stdint.h>

namespace AESencryption {

struct InitVector{
	uint8_t data[AESconstants::BLOCK_SIZE];
};

struct Key;									// -Declaring struct Key and class Cipher to use them as arguments in functions
std::ostream& operator << (std::ostream& ost, const Key& k);

class Cipher;									// Declare cipher class, so we can make it a friend of Key structure

struct Key {
public:
	enum struct LenBits {_128 = 128,_192 = 192,_256 = 256};			// -Allowed AES key lengths
	enum struct OpMode {
		ECB,								// -Electronic Code Book (not recommended).
		CBC,								// -Cipher Block Chaining.
	};
private:
	uint8_t*data = NULL;
	LenBits	lenBits;							// -Length in bits.
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
	Key(LenBits, OpMode);
	Key(const uint8_t* const _key, LenBits, OpMode);
public:
	Key(const char*const fname);						// -Building from binary file.
	Key(const Key&);
	~Key();

	Key& operator =  (const Key&);
	bool operator == (const Key&) const;
	friend std::ostream& operator << (std::ostream& ost, const Key& k);

	OpMode getOpMode() const{ return this->opMode_; }
	size_t getLenBytes() const {return this->lenBytes;}

	void save(const char*const fname) const;				// -Saving information in a binary file.
private:
	void set_IV(const InitVector source);					// -Sets initial vector by copying the array passed as argument
	bool IVisInitialized() const { return this->initializedIV; }
	void write_IV(uint8_t*const destination) const {			// -Writes IV in destination
		for(int i = 0; i < AESconstants::BLOCK_SIZE; i++)
			destination[i] = this->IV.data[i];			// -Warning: We are supposing we have at least 16 bytes of space in destination
	}
	void write_Key(uint8_t*const destination) const {			// -Writes key in destination. Warning: We're supposing we have enough space in
		for(size_t i = 0; i < this->lenBytes; i++) destination[i] = this->data[i]; //  destination array.
	}
};
};
#endif