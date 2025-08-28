#include"../../include/cipher.hpp"
#include<iostream>

class TXT {									// -Handling .txt files
	char* name 	= NULL;
	char* content	= NULL;							// -Text file content.
	unsigned size	= 0;

	public:
	TXT() : name() {}							// -Just for type declaration.
	TXT(const char* fname);							// -Building from file.
	TXT(const TXT&);
	~TXT() {
		if(this->name != NULL) delete [] this->name;
		this->name = NULL;
		if(this->content != NULL) delete[] this->content;
		this->content = NULL;
		this->size = 0;
	}

	TXT& operator = (const TXT&);
	void save(const char* fname = NULL) const;
	void printName() const{ if(this->name != NULL) std::cout << this->name; }

	friend void encrypt(TXT& txt, AESencryption::Cipher& e) {				// -Encrypts using the operation mode defined in Key object
		e.encrypt(txt.content, txt.size);
		txt.save();							// -The reason of the existence of these friend functions is to be capable of
	}									//  encrypt and decrypt many files with the same Cipher object while maintaining
										//  attributes of txt object private
	friend void decrypt(TXT& txt, AESencryption::Cipher& e) {				// -Decrypts using the operation mode defined in Key object
		e.decrypt(txt.content, txt.size);
		txt.save();
	}
};