// -Handling text files.
// -Won't writing new files, just modifying existing ones.

#include"AES.hpp"
#include"FileName.hpp"

#ifndef _INCLUDED_TXT_
#define  _INCLUDED_TXT_

class TXT {
	FileName name;
    unsigned size = 0;
    char* content = NULL; // Text file content.

    public:
    TXT() : name() {} // -Just for type declaration.
    TXT(const char* fname); // Building from file.
    TXT(FileName& fname);
    TXT(const TXT&);
    ~TXT();

	TXT& operator = (const TXT&);
    void save(const char* fname = NULL);
    FileName::Extension fileExtension() {return name.getExtension();}

    // -The initial vector utilized in encryption is written in 'IVlocation'.
	friend void encryptCBC(TXT& txt, const AES& e);
	friend void decryptCBC(TXT& txt, const AES& e);
};
#endif