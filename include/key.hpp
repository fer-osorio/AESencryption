#ifndef KEY_HPP
#define KEY_HPP

#include<iostream>
#include<stddef.h>
#include<stdint.h>

namespace AESencryption {

struct Key;									// -Declaring struct Key and class Cipher to use them as arguments in functions
std::ostream& operator << (std::ostream& ost, const Key& k);

class Cipher;									// Declare cipher class, so we can make it a friend of Key structure

struct Key {
public:
	enum struct LenBits {_128 = 128,_192 = 192,_256 = 256};			// -Allowed AES key lengths
private:
	uint8_t*data = NULL;
	LenBits	lenBits;							// -Length in bits.
	size_t	lenBytes;							// -Length in bytes.

	friend Cipher;
	// The following two private constructors can only be acceced by Cipher class, the intention is to have well-constructed keys for the user.
	Key();
	Key(LenBits);
	Key(const uint8_t* const _key, LenBits);
public:
	Key(const char*const fname);						// -Building from binary file.
	Key(const Key&);
	~Key();

	Key& operator =  (const Key&);
	bool operator == (const Key&) const;
	friend std::ostream& operator << (std::ostream& ost, const Key& k);

	size_t getLenBytes() const {return this->lenBytes;}

	void save(const char*const fname) const;				// -Saving information in a binary file.
private:
	// -Writes IV in destination
	// -Warning: We are supposing we have at least 16 bytes of space in destination
	void write_IV(uint8_t*const destination) const;
	// -Writes key in destination. Warning: We're supposing we have enough space in
	//  destination array.
	void write_Key(uint8_t*const destination) const;
};
};
#endif