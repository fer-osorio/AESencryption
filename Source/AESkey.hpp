// -Handling the keys for AES.
#include <iostream>

#ifndef _INCLUDED_AESKEY_
#define  _INCLUDED_AESKEY_
struct AESkey {
	enum Length {
		_128 = 128,
		_192 = 192,
		_256 = 256
	};
	private:
	Length length;
	unsigned lenBytes; // -Length in bytes.
	char* key = NULL;

	public:
	AESkey(const char* const, Length);
	AESkey(const AESkey&);
	~AESkey();

	AESkey& operator = (const AESkey&);
};
#endif
