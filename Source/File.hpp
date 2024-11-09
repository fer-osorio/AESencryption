// -Set of structures representing files. The intention is to handle files for its encryption
#include "AES.hpp"

#ifndef _INCLUDED_FILE_
#define _INCLUDED_FILE_
#define NAME_MAX_LEN 4096

namespace File {

/*
Valid file name or path grammar

'l' will denote letters in English alphabet, either lower case or upper case.
	For convenience, we will admit '_' and '-' as letters
'd' for digits 0, 1,..., 9
Sld	string of letters and digits that always starts with a letter
FN  File Name
PT  Path
Sled string of letters, digits and spaces. It never starts or ends with a space
FNWE File Name With Spaces

Sld	->	l·Sld	| l·d·Sld	|	l	|	l·d										// -Concatenation of letters and digits that always start with a letter
Sled->	l·SPACES·Sled	| l·d·SPACES·Sled	|	l	|	l·d						// -Concatenation of letters and digits that always start with a letter

FN	->	Sld·FN	|	l															// -File Name can not start with a digit; a single letter can be a File Name
FN	->	.Sld·FN |	FN.Sld·FN	|	.Sld										// -Can not finish with a point nor have two consecutive points

FN  ->  "FNWE"                                                                  // -If double quotes are presented at the beginning of the string, the grammar
FNWE->	Sled·FN	|	l															//	accepts spaces in the middle of the string until the next double quote is found
FNWE->	.Sled·FN|	FN.Sled·FN	|	.Sled

FN  ->  FN/·Sld·FN   |   ../FN	|	/·Sld·FN									// -Considering file paths (Absolute Paths and Relative Paths) as file names

Note: SPACES can be represented by single spaces, or a concatenation of spaces
*/

struct FileName {
	enum Extension {
		NoExtension,															// -The name of the file has no extension.
		Unrecognised,															// -Extension can't be handled.
		bmp,																	// -Image with bmp format.
		txt,																	// -Text file.
		key																		// -Key generated for encryption method.
	};

	private:
	static const char*	supportedExtensions[3];									// -Operations with the extension.
	enum CharType {letter, digit, dot, underscore, hyphen, slash, space, singleQuote ,doubleQuote, notAllowed, zero};

	Extension	extension 			= NoExtension;
	unsigned	size				= 0;
	char* 		string 				= NULL;										// -File name.
	mutable int	currentStringIndex	= 0;										// -We will use this to analyze and validate the 'string' atribute
	bool		beginsDoubleQuote 	= false;									// -Starting with quotes will allow spaces in the middle of Sld strings, but will
	bool		beginsSingleQuote 	= false;									//	require to finish the string with the corresponding quote
	bool        allowSpaces         = false;									// -This will allow spaces in the middle of Sld strings

	Extension isSupportedExtension(const char[]) const;							// -Compares its input with the strings in supportedExtension array
	static CharType characterType(const char c);								// -True for the character that may appear in the file name, false in other case

	bool Sld(const char str[])const;											// -The returned bool flags the founding of zero byte or the characters '\'' or '"'
	void FN(const char str[]) const;

	public:
	FileName() {}
	FileName(const char* _fileName, bool acceptSpaces = false);
	FileName(const FileName& nm);
	FileName& operator = (const FileName& nm);
	~FileName() {
		if(this->string != NULL) delete[] this->string;
		this->string = NULL;
		size = 0;
	}
	void print(const char*const atBeginning = NULL, const char*const atEnd = NULL) const{ std::cout << atBeginning << this->string << atEnd; }
	void println() const{ std::cout << this->string << '\n'; }
	void writestring(char*const destiantion) const;
	unsigned 	getSize() 	   const{ return size;	}
	Extension 	getExtension() const{ return extension; }
	FileName returnThisNewExtension(Extension newExt) const; 					// -Keeps same name, changes the extension. No range checking needed, constructor
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
	void save(const char* fname = NULL) const;
	FileName::Extension fileExtension() const{ return name.getExtension(); }
	void printName(const char*const atBeginning = NULL, const char*const atEnd = NULL) const{ this->name.print(atBeginning, atEnd); }

	friend void encrypt(TXT& txt, AES::Cipher& e) {								// -Encrypts using the operation mode defined in Key object
		e.encrypt(txt.content, txt.size);
		txt.save();																// -The reason of the existence of these friend functions is to be capable of
	}																			//	encrypt and decrypt many files with the same Cipher object while maintaining
																				//	attributes of txt object private
	friend void decrypt(TXT& txt, AES::Cipher& e) {								// -Decrypts using the operation mode defined in Key object
		e.decrypt(txt.content, txt.size);
		txt.save();
	}
};

class Bitmap;																	// -The intention is to use the name Bitmap in the next function
std::ostream& operator << (std::ostream& st, const Bitmap& bmp);				// -What we want is to make this function visible inside the name space scope
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

	void save(const char* fname) const;												// -Saves in memory
	Bitmap& operator = (const Bitmap& bmp);
	friend std::ostream& operator << (std::ostream& st, const Bitmap& bmp);

	friend void encrypt(Bitmap& bmp, AES::Cipher& e) {							// -Encrypts using the operation mode defined in Key object
		e.encrypt(bmp.data, bmp.ih.SizeOfBitmap);
    	bmp.save(bmp.name);														// -The reason of the existence of these friend functions is to be capable of
	}																			//	encrypt and decrypt many files with the same Cipher object while maintaining
																				//	attributes of bmp object private
	friend void decrypt(Bitmap& bmp, AES::Cipher& e) {							// -Decrypts using the operation mode defined in Key object
		e.decrypt(bmp.data, bmp.ih.SizeOfBitmap);
    	bmp.save(bmp.name);
	}
};
};
#endif