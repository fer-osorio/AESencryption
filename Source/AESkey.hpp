// -Handling the keys for AES.
#include <iostream>

struct AESkey {
	private: enum Length {
		_128 = 128,
		_192 = 192,
		_256 = 256
	} length ;
	unsigned lenBytes; // -Length in bytes.
	char* key = NULL;

	public:
	AESkey(const char* const, Length);
	AESkey(const AESkey&);
	~AESkey();

	AESkey& operator = (const AESkey&);
};