#include"FileName.hpp"

FileName::FileName(const char* _fileName, unsigned rightPadding) {
    unsigned i;
    int pointIndex = -1;
    if(_fileName != NULL) {
	    while(_fileName[this->nameSize] != 0 && this->nameSize <= MAX_NAME_LEN) {  // Upper bound for the name length
	        if(_fileName[this->nameSize] == '.') pointIndex = (int)this->nameSize; // Determines index of last point
	        this->nameSize++;
	    }
	    //this->nameSize++;
	    if(rightPadding > 128) rightPadding = 128;
	    this->nameString = new char[this->nameSize + rightPadding + 4];
	    for(i = 0; i < this->nameSize; i++) this->nameString[i] = _fileName[i]; // Copying file name into nameString

	    this->nameString[i] = 0;

	    if(pointIndex >= 0 && pointIndex <= MAX_NAME_LEN - 3)
	        extension = isSupportedExtension(&_fileName[pointIndex + 1]);
	    else extension = NoExtension;
	}
	std::cout << "\n Name size = " << nameSize << '\n' << "Name: " << this->nameString << '\n';
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
		for(unsigned i = 0; i < nm.nameSize; i++)
			this->nameString[i] = nm.nameString[i];
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

FileName::Extension FileName::isSupportedExtension(const char* str) {
    if(str == NULL || str[0] == 0) return FileName::NoExtension;
    Extension temp[4] = {bmp, txt, key, Unrecognised};
    int i, j = 0;
    for(i = 0; i < 3 && supportedExtensions[i][j] != 0; i++) {
        for(j = 0; str[j] == supportedExtensions[i][j]; j++) {
            if(supportedExtensions[i][j] == 0) break;
        }
    }
    return temp[--i];
}
