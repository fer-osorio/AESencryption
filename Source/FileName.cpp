#include"FileName.hpp"

FileName::FileName(const char* _fileName) {
	while(_fileName[this->nameSize++] != 0) {
	    if(_fileName[this->nameSize-1]=='.') pointIndex = (int)this->nameSize-1;
	}
    // -The '+5' part is for future editions in extension.
	if(this->pointIndex < 0) this->nameString = new char[this->nameSize + 6];
	else this->nameString = new char[this->nameSize + 1];
	for(unsigned i = 0; i < this->nameSize; i++)
	    this->nameString[i] = _fileName[i];
	if(pointIndex >= 0) {
        extension = isSupportedExtension(&_fileName[pointIndex+1]);
	} else
	    extension = NoExtension;
}

FileName::FileName(const FileName& nm) : extension(nm.extension),
    nameSize(nm.nameSize), pointIndex(nm.pointIndex) {
	this->nameString = new char[nm.nameSize];
	for(unsigned i = 0; i < nm.nameSize; i++)
		this->nameString[i] = nm.nameString[i];
}

FileName& FileName::operator = (const FileName& nm) {
	if(this != &nm) {
		this->~FileName();
		this->extension = nm.extension;
		this->nameSize = nm.nameSize;
		this->pointIndex = nm.pointIndex;
		this->nameString = new char[nm.nameSize];
		for(unsigned i = 0; i < nm.nameSize; i++)
			this->nameString[i] = nm.nameString[i];
	}
	return *this;
}

FileName FileName::returnThisNewExtension(Extension newExt) {
    FileName   r = *this;
    int i = r.pointIndex;
    switch(newExt) {
        case Unrecognised:    // -Nothing to do. Returning a copy of *this.
            break;
        case NoExtension:     // -Erasing point and extension.
            if(i >= 0) {      // -In the case i<0 we already have what we want.
                while(r.nameString[i] != 0) {
                    r.nameString[i++] = 0;
                    --r.nameSize;
                }
                r.extension = NoExtension;
                r.pointIndex = -1; // No point.
            }
            break;
        case bmp:         // Changing extension.
            if(r.extension != bmp) {
                if(i < 0) {
                    i = (int)r.nameSize; // -No point, we go to the end.
                    r.nameString[i] = '.';
                    r.pointIndex = i;
                    ++r.nameSize;
                }
                r.nameString[++i] = 'b';
                r.nameString[++i] = 'm';
                r.nameString[++i] = 'p';
                r.nameString[++i] = 0;
                r.nameSize += 4;
                r.extension = bmp;
            }
            break;
        case txt:
            if(r.extension != txt) {
                if(i < 0) {
                    i = (int)r.nameSize; // -No point, we go to the end.
                    r.nameString[i] = '.';
                    r.pointIndex = i;
                    ++r.nameSize;
                }
                r.nameString[++i] = 't';
                r.nameString[++i] = 'x';
                r.nameString[++i] = 't';
                r.nameString[++i] = 0;
                r.nameSize += 4;
                r.extension = txt;
            }
            break;
        case key:
            if(r.extension != key) {
                if(i < 0) {
                    i = (int)r.nameSize; // -No point, we go to the end.
                    r.nameString[i] = '.';
                    r.pointIndex = i;
                    ++r.nameSize;
                }
                r.nameString[++i] = 'k';
                r.nameString[++i] = 'e';
                r.nameString[++i] = 'y';
                r.nameString[++i] = 0;
                r.nameSize += 4;
                r.extension = key;
            }
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
