#include"File.hpp"
#include<fstream>
#include<cstring>
#include<exception>

static void throwMessage_cerr(const char callerFunction[], const char message[]) {
    if(callerFunction == NULL) return;
    std::cerr << "In file Source/File.cpp, function " << callerFunction << ": " << message << '\n';
}

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

const StringFileNameAnalize::Extension  StringFileNameAnalize::SupportedExtension[2]= { bmp,   txt };
const char* 	StringFileNameAnalize::SupportedExtensionString[2]                  = {"bmp", "txt"};
const size_t	StringFileNameAnalize::SupportedExtensionAmount	    = sizeof(SupportedExtension) / sizeof(SupportedExtension[0]);
const size_t 	StringFileNameAnalize::extensionStringAmount 		= sizeof(SupportedExtensionString) / sizeof(SupportedExtensionString)[0];

StringFileNameAnalize::Extension StringFileNameAnalize::getExtension(const char fileName[]) {
    if(fileName == NULL) {
        std::cerr << "In file Source/NTRUencryption.cpp, function static FileExtensions getExtension(const char fileName[]). filename == NULL...\n";
        return Unrecognized;
    }
    int i = -1;
    size_t j;
    while(fileName[++i] != 0) {}                                                // -Looking for end of string
    while(fileName[i] != '.' && i > 0) {i--;}                                   // -Looking for last point

    if(i >= 0) {
        for(i++, j = 0; j < SupportedExtensionAmount; j++) {
            if(strcmp(&fileName[i], SupportedExtensionString[j]) == 0) return SupportedExtension[j];
        }
        return Unrecognized;
    }
    return NoExtension;                                                         // -Could not find the point
}

StringFileNameAnalize::CharType StringFileNameAnalize::characterType(const char c){                       // -Just checks if the character may be used in a File Name
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

void StringFileNameAnalize::cerrSyntaxErrMsg(const char msg[]) {
    const char SinErr[] = "Syntax Error: ";
    size_t sz = strlen(SinErr) + this->currentIndex;
    unsigned i;
    std::cerr << SinErr;
    std::cerr << this->str << std::endl;
    for(i = 0; i < sz; i++) std::cerr << ' ';
    std::cerr << "^~~~ " << msg << std::endl;
    if(isDigit(this->str[this->currentIndex]) || this->str[this->currentIndex] == ' ') {
        if(isDigit(this->str[this->currentIndex]))
            while(isDigit(this->str[this->currentIndex])) this->currentIndex++;
        else
            while(this->str[this->currentIndex] == ' ') this->currentIndex++;
    } else
        this->currentIndex++;
    if(this->str[this->currentIndex] != 0 && this->currentIndex < this->size) {
        this->FN();
    }
}

bool StringFileNameAnalize::Sld() {
    if(!isLetter(this->str[this->currentIndex])) {                              // -This ensures we have a letter at the beginning of the string
        if(isDigit(this->str[this->currentIndex])) {
            this->cerrSyntaxErrMsg("File name can not start with a digit.");
            return false;
        }
        this->cerrSyntaxErrMsg("Expected a character from English alphabet.");
        return false;
    }
    unsigned i = 0;
    for(i = ++this->currentIndex; isLetterOrDigit(this->str[i]) || this->str[i] == ' '; i++) {} // -Running trough letters, digits and spaces
    this->currentIndex = i;

    if(this->str[this->currentIndex] == 0) {
        if(this->str[this->currentIndex-1] == ' ') {
            this->cerrSyntaxErrMsg("File Name/Path can not finish with spaces.");
            return false;
        }
        return true;
    }
    return this->FN();
}

bool StringFileNameAnalize::FN() {
    CharType ct = characterType(this->str[this->currentIndex]);
    switch(ct) {
        case slash:                                                             // -Allowing slash for file paths
            this->currentIndex++;
            return this->Sld();
        case letter:
        case underscore:
        case hyphen:
            return this->Sld();                                // -Read (always starting with a letter) letters, digits and (if allowed) spaces;
            break;                                                              //  when a proper ending character is found (0,'\'','"',' ') then return
        case dot:                                                               // -Cases for dot
            if(this->str[++this->currentIndex] == '.') {                        // -The string "../" is allowed as a sub-string so we can use relative paths
                if(this->str[++this->currentIndex] == '/') {
                    this->currentIndex++;
                    return this->FN();
                } else {
                    this->cerrSyntaxErrMsg("Syntax Error: Expected '/' character.");
                    return false;
                }
            } else {
                return this->Sld();                            // -This lines can be interpreted as: Read (always starting with a letter) letters,
            }                                                                   //  digits and (if allowed) spaces; when a proper ending character is found
        case digit:
            this->cerrSyntaxErrMsg("File name can not start with a digit.");
            return false;
        case space:
            this->cerrSyntaxErrMsg("File name can not start with a space.");
            return false;
        case singleQuote:
            this->cerrSyntaxErrMsg("Not Expecting a single quote here.");
            return false;
        case doubleQuote:
            this->cerrSyntaxErrMsg("Not expecting a double quote here.");
            return false;
        case notAllowed:
            this->cerrSyntaxErrMsg("Unexpected character/symbol.");
            return false;
        case zero:
            this->cerrSyntaxErrMsg("Unexpected end of string.");
            return false;
    }
    return false;
}

StringFileNameAnalize::StringFileNameAnalize(const char _str_[]): str(_str_) {
    if(this->str != NULL) while(this->str[this->size] != 0) this->size++;
}

bool StringFileNameAnalize::isValidFileName(const char str[]) {                 // -Validating string as a file name
    StringFileNameAnalize s(str);
    return s.FN();
}

/******************************************************************* Text files (.txt files) **********************************************************************/

TXT::TXT(const char* fname) { // -Building from file.
    std::ifstream file;
    file.open(fname);
    if(file.is_open()) {
        this->name = new char[strlen(fname)];
        strcpy(this->name, fname);
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        this->size = fileSize;
        file.seekg(0, std::ios::beg);
        this->content = new char[fileSize];
        file.read(this->content, fileSize);
        file.close();
    } else {
        throwMessage_cerr("TXT::TXT(const char* fname)", "Could not open file.");
        throw std::runtime_error("Could not open file.");
    }
}

TXT::TXT(const TXT& t): size(t.size) {
    this->name = new char[strlen(t.name)];
    strcpy(this->name, t.name);
    this->content = new char[t.size];
    for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
}

void TXT::save(const char* fname)  const{                                       // -The user can provide a name for the file
    std::ofstream file;
    if(fname != NULL)
        file.open(fname);
    else                                                                        // -If no name provided, the string inside attribute name will be used
        file.open(this->name);
    if(file.is_open()) {
        file.write(this->content, this->size);
        file.close();
    } else {
        throwMessage_cerr("void TXT::save(const char* fname)", "File could not be written.");
        throw std::runtime_error("File could not be written.");
    }
}

TXT& TXT::operator = (const TXT& t) {
    if(this != &t) {
        if(this->name != NULL) delete[] this->name;
        this->name = new char[strlen(t.name)];
        strcpy(this->name, t.name);
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
    const char thisFuncName[] = "Bitmap::Bitmap(const char* fname)";
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
            throwMessage_cerr(thisFuncName, "Not a valid bitmap file.");
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throwMessage_cerr(thisFuncName, "File could not be opened.");
        throw std::runtime_error("File could not be opened.");
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
    const char thisFuncName[] = "void Bitmap::save(const char *fname)";
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
            throwMessage_cerr(thisFuncName, "Not a valid bitmap file");
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throwMessage_cerr(thisFuncName, "File could not be written");
        throw std::runtime_error("File could not be written.");
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
