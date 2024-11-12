#include"File.hpp"
#include<fstream>
#include<cstring>

using namespace File;

/*************************************************************** Handling the name of the files *******************************************************************/

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

FileName::Extension FileName::isSupportedExtension(const char str[]) const{
    if(str == NULL || str[0] == 0) return FileName::NoExtension;
    Extension temp[3] = {bmp, txt, aeskey};
    int i, j = 0;
    for(i = 0; i < this->extensionStringAmount && extensionString[i][j] != 0; i++) {
        for(j = 0; str[j] == extensionString[i][j]; j++) {
            if(extensionString[i][j] == 0) return temp[i];
        }
    }
    return Unrecognised;
}

FileName::CharType FileName::characterType(const char c){                       // -Just checks if the character may be used in a File Name
    if((c > 64 && c < 91) || (c > 96 && c < 123)) return letter;                // -Letters
    if(c > 47 && c < 58) return digit;                                          // -Decimal digits
    if(c == '.') return dot;                                                    // -And finally special symbols
    if(c == '_') return underscore;                                             //  ...
    if(c == '-') return hyphen;                                                 //  ...
    if(c == '/') return slash;                                                  //  ...
    if(c == ' ') return space;                                                  //  ...
    if(c == '\'')return singleQuote;                                            //  ...
    if(c == '"') return doubleQuote;                                            //  ...
    if(c == 0)   return zero;

    return notAllowed;                                                          // -Anything else is a not allowed symbol
}

static bool isLetter(const char c) {
    return (c > 64 && c < 91) ||                                                // -Upper case letters
           (c > 96 && c < 123)||                                                // -Lower case letters
            c == '_' || c == '-';                                               // -Seeking simplicity, '-' and '_' will be consider as letters
}

static bool isDigit(const char c) {
    return (c > 47 && c < 58);
}

static bool isLetterOrDigit(const char c) {
    return (c > 47 && c < 58) ||                                                // -Decimal digits
           (c > 64 && c < 91) ||                                                // -Upper case letters
           (c > 96 && c < 123)||                                                // -Lower case letters
            c == '_' || c == '-';                                               // -Seeking simplicity, '-' and '_' will be consider as letters
}

bool FileName::Sld(const char str[]) const{
    if(!isLetter(str[this->currentStringIndex])) {                              // -This ensures we have a letter at the beginning of the string
        if(isDigit(str[this->currentStringIndex]))
            throw "Syntax Error: File name can not start with a digit...\n";
        throw "Syntax Error: Expected an character from English alphabet...\n";
    }
    int i = 0;
    if(this->allowSpaces){                                                      // -If file name starts with single/double quote or the constructor sets as so
        for(i = ++this->currentStringIndex; isLetterOrDigit(str[i]) || str[i] == ' '; i++) {} // -Running trough letters, digits and spaces
    } else
        for(i = ++this->currentStringIndex; isLetterOrDigit(str[i]); i++) {}    // -Running trough letters and digits

    this->currentStringIndex = i;

    if(str[this->currentStringIndex] == 0) {
        if(this->beginsSingleQuote) throw "Syntax Error: String started with single quote, then it should finish with double quotes\n";
        if(this->beginsDoubleQuote) throw "Syntax Error: String started with double quote, then it should finish with double quotes\n";
        return true;
    }
    if(this->beginsSingleQuote && str[this->currentStringIndex] == '\'') { // -Starting with single quote, finishing with single quote
        if(str[this->currentStringIndex-1] == ' ') throw "Syntax Error: File Name/Path can not finish with spaces...\n";
        return true;
    }
    if(this->beginsDoubleQuote && str[this->currentStringIndex] == '"' ) { // -Starting with double quote, finishing with double quote
        if(str[this->currentStringIndex-1] == ' ') throw "Syntax Error: File Name/Path can not finish with spaces...\n";
        return true;
    }
    if(str[this->currentStringIndex] == ' ') return true;                       // -At this point, a space is a proper ending for the input string
    return false;
}

void FileName::FN(const char str[]) const{
    CharType ct = FileName::characterType(str[this->currentStringIndex]);
    switch(ct) {
        case letter:                                                            // -We can interpret this lines of codes as: A file name con start with a letter,
        case underscore:                                                        //  a underscore or a hyphen
        case hyphen:                                                            //  ...
        case slash:                                                             // -Allowing slash for file paths
            try { if(this->Sld(str)) return; }                                  // -This lines can be interpreted as: Read (always starting with a letter) letters,
            catch(const char[]) { throw; }                                      //  digits and (if allowed) spaces; when a proper ending character is found
            break;                                                              //  (0, '\'', '"',' ') then return, otherwise continue reading
        case dot:                                                               // -Cases for dot
            if(str[++this->currentStringIndex] == '.') {                        // -The string "../" is allowed as a sub-string so we can use relative paths
                if(str[++this->currentStringIndex] == '/') {                    //  ...
                    try { this->FN(str); }                                      //  ...
                    catch(const char[]) { throw; }                              //  ...
                } else throw "Syntax Error: Expected '/' character...\n";
            } else {
                try { if(this->Sld(str)) return; }                              // -This lines can be interpreted as: Read (always starting with a letter) letters,
                catch(const char[]) { throw; }                                  //  digits and (if allowed) spaces; when a proper ending character is found
            }
        break;
        case digit:
            throw "Syntax Error: File name can not start with a digit...\n";
        case space:
            throw "Syntax Error: Not expecting a space here...\n";
        case singleQuote:
            throw "Syntax Error: Not expecting a single quote here...\n";
        case doubleQuote:
            throw "Syntax Error: Not expecting a double quote here...\n";
        case notAllowed:
            throw "Syntax Error: Unexpected character/symbol...\n";
        case zero:
            throw "Syntax Error: Unexpected end of string...\n";
    }
    try { this->FN(str); }
    catch(const char[]) { throw; }
}

FileName::FileName(const char* fileName_, bool acceptSpaces): allowSpaces(acceptSpaces) {
    int i = 0, j = 0, markBeginning = 0, markEnd = 0;                           // -Markers for the beginning and end of input string
    int pointIndex = -1;

    if(fileName_ == NULL)
        throw   "In Source/File.cpp,function FileName::FileName(const char* fileName_, unsigned rightPadding).\n"
                "Could not build 'FileName' object from null fileName_ input.\n";
    if(fileName_[0] == 0)
        throw   "In Source/File.cpp,function FileName::FileName(const char* fileName_, unsigned rightPadding).\n"
                "Could not build 'FileName' object from trivial string (fileName_[0] == 0).\n";

    while(fileName_[i] == ' ' || fileName_[i] == '\t') i++;                     // -Ignoring the spaces and tabs that could be at the beginning of the input

    if(fileName_[i] == '\'' || fileName_[i] == '"') {                           // -We can interpret this as: Spaces are allowed; read till the next double/single
        if(fileName_[i] == '\'')this->beginsSingleQuote = true;                 //  quote
        else                    this->beginsDoubleQuote = true;
        this->allowSpaces = true;
        i++;
    }
    this->currentStringIndex = markBeginning = i;                               // -Marking the beginning of the file name inside the string

    try{
        this->FN(fileName_);
    } catch(const char exp[]) {
        std::cout << exp;
        throw "In file Source/File.cpp, function FileName::FileName(const char* fileName_, unsigned rightPadding)\n";
    }
    markEnd = this->currentStringIndex;
    this->size = unsigned(markEnd - markBeginning);
    this->string = new char[this->size + 1];

	for(i = markBeginning, j = 0; i < markEnd; i++, j++) this->string[j] = fileName_[i];
	this->string[j] = 0;
	while(j >= 0 && this->string[j] != '.') j--;
	pointIndex = j;

	if(pointIndex >= 0 && pointIndex <= NAME_MAX_LEN - 3)
	    extension = isSupportedExtension(&fileName_[pointIndex + 1]);
	else extension = NoExtension;
}

FileName::FileName(const FileName& nm): extension(nm.extension), size(nm.size) {
	this->string = new char[nm.size];
	for(unsigned i = 0; i < nm.size; i++)
		this->string[i] = nm.string[i];
}

FileName& FileName::operator = (const FileName& nm) {
	if(this != &nm) {
		this->extension = nm.extension;
		this->size = nm.size;
		if(this->string != NULL) delete[] this->string;
		this->string = new char[nm.size];
		for(unsigned i = 0; i <= nm.size; i++)                                  // -The <= condition is necessary to copy the '0' that ends the string. Remember,
			this->string[i] = nm.string[i];                                     //  this is a formatted string.
	}
	return *this;
}

FileName FileName::returnThisNewExtension(Extension newExt) const{
    if(newExt == NoExtension || newExt == Unrecognised) return *this;           // -In this cases we return a copy of original extension
    FileName r;
    r.size = this->size + strlen(this->extensionString[newExt]);
    r.string = new char[r.size];                                                // -Making room for new extension
    strcpy(r.string, this->string);                                             // -Copying original file name
    strcpy(&r.string[this->size], this->extensionString[newExt]);               // -Adding new extension
    r.extension = newExt;
    return r;
}

void FileName::writestring(char *const destiantion) const{ 					// -Assuming destination has enough space for the String
	if(this->string == NULL) return;
	for(unsigned i = 0; i < this->size; i++) {
		destiantion[i] = this->string[i];
	}
	destiantion[this->size] = 0;
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
    this->name.writestring(nameStr);
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

void TXT::save(const char* fname)  const{                                       // -The user can provide a name for the file
    std::ofstream file;
    char* nameStr = NULL;
    if(fname != NULL) file.open(fname);
    else {                                                                      // -If no name provided, the string inside attribute name will be used
        nameStr = new char[this->name.getSize()];
        this->name.writestring(nameStr);
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

void Bitmap::save(const char *fname) const{
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
