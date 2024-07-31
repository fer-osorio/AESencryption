// -Handling text files.
// -Won't writing new files, just modifying existing ones.

#include"AES.hpp"
#include"FileName.hpp"

#ifndef _INCLUDED_TXT_
#define  _INCLUDED_TXT_

class TXT {
	FileName name;
    char* content = NULL; // Text file content.
    unsigned size = 0;

    public:
    TXT() : name() {} // -Just for type declaration.
    TXT(const char* fname); // Building from file.
    TXT(FileName& fname);
    TXT(const TXT&);
    ~TXT() {
    	if(this->content != NULL) delete[] this->content;
    	this->content = NULL;
    	this->size = 0;
    }

	TXT& operator = (const TXT&);
    void save(const char* fname = NULL);
    FileName::Extension fileExtension() { return name.getExtension(); }
    void printName() { std::cout << name.getNameString(); }

    friend void encryptECB(TXT& txt, const AES::Cipher& e);
	friend void decryptECB(TXT& txt, const AES::Cipher& e);

    // -The initial vector utilized in encryption is written in 'IVlocation'.
	friend void encryptCBC(TXT& txt, const AES::Cipher& e);
	friend void decryptCBC(TXT& txt, const AES::Cipher& e);

	friend void encryptPIVS(TXT& txt, const AES::Cipher& e);
	friend void decryptPIVS(TXT& txt, const AES::Cipher& e);
};
#endif