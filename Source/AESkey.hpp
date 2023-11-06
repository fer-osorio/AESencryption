// -Class AESkey will hold the necessary information for the decryption of
//  whatever we have encrypted.
#include <iostream>

#ifndef _INCLUDED_AESKEY_
#define  _INCLUDED_AESKEY_
struct AESkey {
	enum Length {
		_128 = 128,
		_192 = 192,
		_256 = 256
	};
	enum OperationMode {
		ECB, // -Electronic Code Book (not recommended).
		CBC, // -Cipher Block Chaining.
		CFB,
		OFB,
		CTR
	};
	private:
	Length 	 length;	// -Length in bits.
	unsigned lenBytes;  // -Length in bytes.
	OperationMode opM;
	char* key = NULL;
	char IV[16] = {0, 0, 0, 0,	// -Initial vector for the CBC operation mode.
				   0, 0, 0, 0,	// -This default value (just zeros) is left
				   0, 0, 0, 0,	//  for the case in which we do not use CBC.
				   0, 0, 0, 0};

	public:
	AESkey(const char* const,			// -Initializing all
		   Length, 						//  arguments from
		   OperationMode,				//	'outside' of the
		   const char* const = NULL);	//	object.
	AESkey(const AESkey&);
	AESkey(const char*const fname);		// -Building from binary file.
	~AESkey();

	AESkey& operator = (const AESkey&);

	inline void set_OperationMode(OperationMode _opM) {opM = _opM;}
	inline void set_IV(const char*const _IV) {
		for(int i = 0; i < 16; i++) this->IV[i] = _IV[i];
	}
	inline void write_IV(char*const destination) const {
		for(int i = 0; i < 16; i++) destination[i] = this->IV[i];
	}
	inline const char* getIV() const {return IV;}
	inline void write_Key(char*const destination) const {
		for(unsigned i = 0; i < lenBytes; i++) destination[i] = this->key[i];
	}
	inline unsigned get_LenBytes() const {return this->lenBytes;}
	void save(const char* const) const; // -Saving information in a binary file.
};
#endif