// -This class was created to handle the names of the files that this program is capable to deal with.
#include<iostream>

#ifndef _INCLUDED_FILENAME_
#define _INCLUDED_FILENAME_

#define MAX_NAME_LEN 256

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
#endif