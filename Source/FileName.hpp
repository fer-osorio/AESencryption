// -This class was created to handle the names of the files that this program
//  is capable to deal with.
#include<iostream>

#ifndef _INCLUDED_FILENAME_
#define  _INCLUDED_FILENAME_

struct FileName {
	enum Extension {
		NoExtension, // -The name of the file has no extension.
		Unrecognised,// -Extension can't be handled.
		bmp,		 // -Image with bmp format.
		txt,		 // -Text file.
		key			 // -Key generated for encryption method.
	};

	private:
	Extension extension = NoExtension;
	unsigned nameSize = 0;
	int pointIndex = -1; // -The value -1 represents "no point".
	char* nameString = NULL; // -File name.

	// -Operations with the extension.
	const char* supportedExtensions[3] = {"bmp", "txt", "key"};
	Extension isSupportedExtension(const char*);

	public:
	FileName() {}	// -Just for type declaration.
	FileName(const char* _fileName);
	FileName(const FileName& nm);
	FileName& operator = (const FileName& nm);
	~FileName() {
		if(this->nameString != NULL) delete[] this->nameString;
		this->nameString = NULL;
		nameSize = 0;
	}
	const char* getNameString() {return nameString;}
	unsigned 	getSize() 		{return nameSize;}
	Extension 	getExtension() 	{return extension;}
	// -Keeps same name, changes the extension
	// -No range checking needed, constructor ensures enough space.
	FileName returnThisNewExtension(Extension newExt);
};
#endif