#include"File.hpp"
#include <fstream>

using namespace File;

/*************************************************************** Handling the name of the files *******************************************************************/

FileName::FileName(const char* _fileName, unsigned rightPadding) {
    unsigned i;
    int pointIndex = -1;

    if(_fileName == NULL) return;                                               // Guarding against null string

	while(_fileName[this->nameSize] != 0 && this->nameSize <= NAME_MAX_LEN) {   // Upper bound for the name length
	    if(_fileName[this->nameSize] == '.') pointIndex = (int)this->nameSize;  // Determines index of last point
	    this->nameSize++;
	}
	if(rightPadding > 128) rightPadding = 128;                                  // Upper bound for right padding
	this->nameString = new char[this->nameSize + rightPadding + 1];
	for(i = 0; i < this->nameSize; i++) this->nameString[i] = _fileName[i];     // Copying file name into nameString

	this->nameString[i] = 0;

	if(pointIndex >= 0 && pointIndex <= NAME_MAX_LEN - 3)
	    extension = isSupportedExtension(&_fileName[pointIndex + 1]);
	else extension = NoExtension;
}

FileName::FileName(const FileName& nm): extension(nm.extension), nameSize(nm.nameSize) {
	this->nameString = new char[nm.nameSize];
	for(unsigned i = 0; i < nm.nameSize; i++)
		this->nameString[i] = nm.nameString[i];
}

FileName& FileName::operator = (const FileName& nm) {
	if(this != &nm) {
		this->extension = nm.extension;
		this->nameSize = nm.nameSize;
		if(this->nameString != NULL) delete[] this->nameString;
		this->nameString = new char[nm.nameSize];
		for(unsigned i = 0; i <= nm.nameSize; i++)                              // -The <= condition is necessary to copy the '0' that ends the string. Remember,
			this->nameString[i] = nm.nameString[i];                             //  this is a formatted string.
	}
	return *this;
}

FileName FileName::returnThisNewExtension(Extension newExt) {
    FileName r = FileName(this->nameString, 4);
    int i = (int)r.nameSize;
    switch(newExt) {
        case Unrecognised:                                                      // -Nothing to do. Returning a copy of *this.
            break;
        case NoExtension:                                                       // -Nothing to do. Returning a copy of *this.
            break;
        case bmp:                                                               // Adding extension.
            r.nameString[i] = '.';
            r.nameString[++i] = 'b';
            r.nameString[++i] = 'm';
            r.nameString[++i] = 'p';
            r.nameString[++i] = 0;
            r.nameSize += 4;
            r.extension = bmp;
            break;
        case txt:
            r.nameString[i] = '.';
            r.nameString[++i] = 't';
            r.nameString[++i] = 'x';
            r.nameString[++i] = 't';
            r.nameString[++i] = 0;
            r.nameSize += 4;
            r.extension = txt;
            break;
        case key:
            r.nameString[i] = '.';
            r.nameString[++i] = 'k';
            r.nameString[++i] = 'e';
            r.nameString[++i] = 'y';
            r.nameString[++i] = 0;
            r.nameSize += 4;
            r.extension = key;
            break;
    }
    return r;
}

void FileName::writeNameString(char *const destiantion) { 					    // -Assuming destination has enough space for the String
	if(this->nameString == NULL) return;
	for(unsigned i = 0; i < this->nameSize; i++) {
		destiantion[i] = this->nameString[i];
		if(this->nameString[i] == 0) {										    // -In case of encounter the end of the string before reaching name size
			this->nameSize = i;
			return;
		}
	}
	destiantion[this->nameSize] = 0;
}

FileName::Extension FileName::isSupportedExtension(const char* str) {
    if(str == NULL || str[0] == 0) return FileName::NoExtension;
    Extension temp[4] = {bmp, txt, key};
    int i, j = 0;
    for(i = 0; i < 3 && supportedExtensions[i][j] != 0; i++) {
        for(j = 0; str[j] == supportedExtensions[i][j]; j++) {
            if(supportedExtensions[i][j] == 0) return temp[i];
        }
    }
    return Unrecognised;
}


/******************************************************************* Text files (.txt files) **********************************************************************/

TXT::TXT(const char* fname): name(fname) { // -Building from file.
    std::ifstream file;
    file.open(fname);
    if(file.is_open()) {
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        this->size = fileSize;
        file.seekg(0, std::ios::beg);
        this->content = new char[fileSize];
        file.read(this->content, fileSize);
        file.close();
    } else {
        char errmsg[] = "\nIn TXT.cpp file, TXT::TXT(const char* fname): "
                        "Could not open file ";
        std::cout << errmsg << fname << '\n';
        throw errmsg;
    }
}

TXT::TXT(FileName& fname): name(fname) {
    std::ifstream file;
    char*const nameStr = new char[this->name.getSize()];
    this->name.writeNameString(nameStr);
    file.open(nameStr);
    if(file.is_open()) {
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        this->size = fileSize;
        file.seekg(0, std::ios::beg);
        this->content = new char[fileSize];
        file.read(this->content, fileSize);
        file.close();
    } else {
        if(nameStr != NULL) delete[] nameStr;
        throw "\nIn Source/File.cpp, function TXT::TXT(FileName& fname): name(fname). Could not open file...\n";
    }
    if(nameStr != NULL) delete[] nameStr;
}

TXT::TXT(const TXT& t): name(t.name), size(t.size) {
    this->content = new char[t.size];
    for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
}

void TXT::save(const char* fname) {                                             // -The user can provide a name for the file
    std::ofstream file;
    char* nameStr = NULL;
    if(fname != NULL) file.open(fname);
    else {                                                                      // -If no name provided, the string inside attribute name will be used
        nameStr = new char[this->name.getSize()];
        this->name.writeNameString(nameStr);
        file.open(nameStr);
    }
    if(file.is_open()) {
        file.write(this->content, this->size);
        file.close();
    } else {
        if(nameStr != NULL) delete[] nameStr;
        throw "File could not be written.";
    }
    if(nameStr != NULL) delete[] nameStr;
}

TXT& TXT::operator = (const TXT& t) {
    if(this != &t) {
        this->name = t.name;
        this->size = t.size;
        if(content != NULL) delete[] content;
        this->content = new char[t.size];
        for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
    }
    return *this;
}


/******************************************************************* BMP images (.bmp files) **********************************************************************/

Bitmap::Bitmap(const char* fname) {
    std::ifstream file;
    file.open(fname, std::ios::binary);
    int i, j, sz = 0;
    if(file.is_open()) {
        file.read((char*)fh.bm, 2);
        if(fh.bm[0] == 'B' && fh.bm[1] == 'M') {
            // -File Header.
            file.read((char*)&fh.size, 4);
            file.read((char*)&fh.reserved1, 2);
            file.read((char*)&fh.reserved2, 2);
            file.read((char*)&fh.offset, 4);

            // -Image Header.
            file.read((char*)&ih.size, 4);
            file.read((char*)&ih.Width, 4);
            file.read((char*)&ih.Height, 4);
            file.read((char*)&ih.Planes, 2);
            file.read((char*)&ih.BitsPerPixel, 2);
            file.read((char*)&ih.Compression, 4);
            file.read((char*)&ih.SizeOfBitmap, 4);
            file.read((char*)&ih.HorzResolution, 4);
            file.read((char*)&ih.VertResolution, 4);
            file.read((char*)&ih.ColorsUsed, 4);
            file.read((char*)&ih.ColorsImportant, 4);
            data = new char[ih.SizeOfBitmap];

            file.read((char*)data, ih.SizeOfBitmap);                            // -Initializing bitmap data

            img = new RGB*[ih.Height];                                          // -Building pixel matrix
            for(i = ih.Height - 1, j = 0; i >= 0; i--, j++) {
                img[j] = (RGB*)&data[3 * i * ih.Width];
            }
            while(fname[sz++] != 0) {}                                          // -Getting name size.
            name = new char[sz];
            for(i = 0; i < sz; i++) name[i] = fname[i];                         // -Copying name
            file.close();
        } else {
            file.close();
            throw "Not a valid bitmap file.";
        }
    } else {
        throw "File could not be opened/created.";
    }
}

Bitmap::Bitmap(const Bitmap& bmp) {
    this->fh.bm[0] = bmp.fh.bm[0];                                              // -Initializing file header.
    this->fh.bm[1] = bmp.fh.bm[1];                                              // ...
    this->fh.size = bmp.fh.size;                                                // ...
    this->fh.reserved1 = bmp.fh.reserved1;                                      // ...
    this->fh.reserved2 = bmp.fh.reserved2;                                      // ...
    this->fh.offset = bmp.fh.offset;                                            // ...

    this->ih = bmp.ih;                                                          // -Initializing image header. Using the default member to member copy.

    ui32 i;                                                                     // -Initializing data.
    this->data = new char[bmp.ih.SizeOfBitmap];
    for(i = 0; i < bmp.ih.SizeOfBitmap; i++) this->data[i] = bmp.data[i];

    this->img = new RGB*[bmp.ih.Height];
    for(i = 0; (int)i < bmp.ih.Height; i++) this->img[i] = bmp.img[i];

    ui32 sz = 0;                                                                // Initializing name
    while(bmp.name[sz++] != 0) {} // -Getting name size.
    name = new char[sz];
    for(i = 0; i < sz; i++) name[i] = bmp.name[i];
}

Bitmap::~Bitmap() {
    if(data != NULL) { delete[] data; data = NULL; }
    if(img  != NULL) { delete[] img;   img = NULL; }
    if(name != NULL) { delete[] name; name = NULL; }
}

void Bitmap::save(const char *fname) {
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        if(fh.bm[0] == 'B' && fh.bm[1] == 'M') {
            file.write((char*)fh.bm, 2);                                        // -File Header.
            file.write((char*)&fh.size, 4);                                     // ...
            file.write((char*)&fh.reserved1, 2);                                // ...
            file.write((char*)&fh.reserved2, 2);                                // ...
            file.write((char*)&fh.offset, 4);                                   // ...

            file.write((char*)&ih.size, 4);                                     // -Image Header.
            file.write((char*)&ih.Width, 4);                                    // ...
            file.write((char*)&ih.Height, 4);                                   // ...
            file.write((char*)&ih.Planes, 2);                                   // ...
            file.write((char*)&ih.BitsPerPixel, 2);                             // ...
            file.write((char*)&ih.Compression, 4);                              // ...
            file.write((char*)&ih.SizeOfBitmap, 4);                             // ...
            file.write((char*)&ih.HorzResolution, 4);                           // ...
            file.write((char*)&ih.VertResolution, 4);                           // ...
            file.write((char*)&ih.ColorsUsed, 4);                               // ...
            file.write((char*)&ih.ColorsImportant, 4);                          // ...
            file.write((char*)data, ih.SizeOfBitmap);                           // ...
            file.close();
        } else {
            file.close();
            throw "Not a valid bitmap file.";
        }
    } else {
        throw "File could not be written.";
    }
}

Bitmap& Bitmap::operator = (const Bitmap &bmp) {
    if(this != &bmp) {                                                          // -Guarding against self assignment
        this->fh.bm[0] = bmp.fh.bm[0];                                          // -Copying file header.
        this->fh.bm[1] = bmp.fh.bm[1];                                          // ...
        this->fh.size = bmp.fh.size;                                            // ...
        this->fh.reserved1 = bmp.fh.reserved1;                                  // ...
        this->fh.reserved2 = bmp.fh.reserved2;                                  // ...
        this->fh.offset = bmp.fh.offset;                                        // ...

        this->ih = bmp.ih;                                                      // -Copying image header. Using the default member to member copy.

        ui32 i;                                                                 // -Copying data.
        if(this->data != NULL) delete[] this->data;
        this->data = new char[bmp.ih.SizeOfBitmap];
        for(i = 0; i < bmp.ih.SizeOfBitmap; i++) this->data[i] = bmp.data[i];

        if(this->img != NULL) delete[] this->img;                               // -Copying pixel matrix
        this->img = new RGB*[bmp.ih.Height];
        for(i = 0; (int)i < bmp.ih.Height; i++) this->img[i] = bmp.img[i];

        ui32 sz = 0;
        while(bmp.name[sz++] != 0) {}                                           // -Getting name size.
        if(this->name != NULL) delete[] this->name;
        this->name = new char[sz];
        for(i = 0; i < sz; i++) this->name[i] = bmp.name[i];                    // -Copying name
    }
    return *this;
}

std::ostream& File::operator << (std::ostream &stream, const Bitmap &bmp) {
    stream << "File Header: ";
    stream << "\n\tbm: " << bmp.fh.bm[0] << bmp.fh.bm[1];
    stream << "\n\tsize: " << bmp.fh.size;
    stream << "\n\treserved1: " << bmp.fh.reserved1;
    stream << "\n\treserved2: " << bmp.fh.reserved2;
    stream << "\n\toffset: " << bmp.fh.offset;

    stream << "\nImage Header: ";
    stream << "\n\tsize: " << bmp.ih.size;
    stream << "\n\twidth: " << bmp.ih.Width;
    stream << "\n\theight: " << bmp.ih.Height;
    stream << "\n\tplanes: " << bmp.ih.Planes;
    stream << "\n\tbits per pixel: " << bmp.ih.BitsPerPixel;
    stream << "\n\tcompression: " << bmp.ih.Compression;
    stream << "\n\timage size: " << bmp.ih.SizeOfBitmap;
    stream << "\n\thorizontal resolution: " << bmp.ih.HorzResolution;
    stream << "\n\tvertical resolution: " << bmp.ih.VertResolution;
    stream << "\n\tcolors used: " << bmp.ih.ColorsUsed;
    stream << "\n\tcolors important: " << bmp.ih.ColorsImportant;

    return stream;
}
