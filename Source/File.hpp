// Files that can be encrypted using this implementation of AES
#include "AES.hpp"

#ifndef _INCLUDED_FILE_
#define _INCLUDED_FILE_
#define NAME_MAX_LEN 256

namespace File {

struct FileName {
	enum Extension {
		NoExtension,															// -The name of the file has no extension.
		Unrecognised,															// -Extension can't be handled.
		bmp,																	// -Image with bmp format.
		txt,																	// -Text file.
		key																		// -Key generated for encryption method.
	};

	private:
	const char* supportedExtensions[3] = { "bmp", "txt", "key" };				// -Operations with the extension.
	Extension extension = NoExtension;
	unsigned nameSize	= 0;
	char* 	 nameString = NULL;													// -File name.

	Extension isSupportedExtension(const char*);								// -Compares its input with the strings in supportedExtension array

	public:
	FileName() {}
	FileName(const char* _fileName, unsigned rightPadding = 0);
	FileName(const FileName& nm);
	FileName& operator = (const FileName& nm);
	~FileName() {
		if(this->nameString != NULL) delete[] this->nameString;
		this->nameString = NULL;
		nameSize = 0;
	}
	const char* getNameString() { return nameString;}
	unsigned 	getSize() 		{ return nameSize;	}
	Extension 	getExtension() 	{ return extension; }

	FileName returnThisNewExtension(Extension newExt); 							// -Keeps same name, changes the extension. No range checking needed, constructor
																				//  ensures enough space.
};

class TXT {																		// -Handling .txt files
	FileName name;
	char* content = NULL;														// Text file content.
	unsigned size = 0;

	public:
	TXT() : name() {}															// -Just for type declaration.
	TXT(const char* fname);														// Building from file.
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

	friend void encryptECB(TXT& txt, const AES::Cipher& e) {
		e.encryptECB(txt.content, txt.size);
    	txt.save();
	}
	friend void decryptECB(TXT& txt, const AES::Cipher& e) {
		e.decryptECB(txt.content, txt.size);
    	txt.save();
	}

	friend void encryptCBC(TXT& txt, const AES::Cipher& e) {
		e.encryptCBC(txt.content, txt.size);
    	txt.save();
	}
	friend void decryptCBC(TXT& txt, const AES::Cipher& e) {
		e.decryptCBC(txt.content, txt.size);
    	txt.save();
	}

	friend void encryptPIVS(TXT& txt, const AES::Cipher& e) {
		e.encryptPIVS(txt.content, txt.size);
    	txt.save();
	}
	friend void decryptPIVS(TXT& txt, const AES::Cipher& e) {
		e.decryptPIVS(txt.content, txt.size);
    	txt.save();
	}
};

class Bitmap;																	// -The intention is to use the name Bitmap in the next function
std::ostream& operator << (std::ostream& st, const Bitmap& bmp);				// -What we want is to make this function visible inside the namespace scope
class Bitmap {																	// -Handling bitmap format images.
	typedef unsigned char  ui08;
	typedef unsigned short ui16;
	typedef unsigned int   ui32;

	struct RGB {
		ui08 red;
		ui08 green;
		ui08 blue;
	};
	struct FileHeader {
		char bm[2];																// [B, M] for bmp files
		unsigned size;  														// File size
		ui16 reserved1;															// Dependent on the originator application
		ui16 reserved2;															// Dependent on the originator application
		ui32 offset;															// Starting address of the image data
	} fh = {0,0,0,0,0,0};

	struct ImageHeader {
		ui32 size;																// Size of this header
		int Width;																// Image width in pixels
		int Height;																// Image height in pixels
		ui16 Planes;															// Number of color planes (must be 1)
		ui16 BitsPerPixel;														// Number of bits per pixel, in this case 24
		ui32 Compression;														// Compression method
		ui32 SizeOfBitmap;														// Size of raw bitmap data
		int HorzResolution; 													// Horizontal pixel per meter
		int VertResolution; 													// Vertical pixel per meter
		ui32 ColorsUsed;														// Colors in the color palette, 0 to default
		ui32 ColorsImportant;													// Zero when every color is important
	} ih = {0,0,0,0,0,0,0,0,0,0,0};

	char* data = NULL;
	RGB** img  = NULL;
	char* name = NULL;

	public:
	Bitmap() {} 																// -Just for type declaration
	Bitmap(const char* fname);
	Bitmap(const Bitmap& bmp);
	~Bitmap();

	void save(const char* fname);												// -Saves in memory
	Bitmap& operator = (const Bitmap& bmp);

	friend void encryptCBC(Bitmap& bmp, const AES::Cipher& e) {
		e.encryptCBC(bmp.data, bmp.ih.SizeOfBitmap);
    	bmp.save(bmp.name);
	}
	friend void decryptCBC(Bitmap& bmp, const AES::Cipher& e) {
		e.decryptCBC(bmp.data, bmp.ih.SizeOfBitmap);
    	bmp.save(bmp.name);
	}

	friend void encryptPIVS(Bitmap& bmp, const AES::Cipher& e) {
		e.encryptPIVS(bmp.data, bmp.ih.SizeOfBitmap);
    	bmp.save(bmp.name);
	}
	friend void decryptPIVS(Bitmap& bmp, const AES::Cipher& e) {
		e.decryptPIVS(bmp.data, bmp.ih.SizeOfBitmap);
    	bmp.save(bmp.name);
	}

	friend std::ostream& operator << (std::ostream& st, const Bitmap& bmp);
};
};
#endif