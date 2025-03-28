#include"File.hpp"
#include<fstream>
#include<cstring>
#include<cmath>
#include<exception>

/*static void cerrWargingMessage(const char callerFunction[], const char message[]){
    if(callerFunction == NULL) return;
    std::cerr << "In file Source/File.cpp, function " << callerFunction << ": " << message << '\n';
}*/

static void cerrMessageBeforeThrow(const char callerFunction[], const char message[]) {
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
        cerrMessageBeforeThrow("TXT::TXT(const char* fname)", "Could not open file.");
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
        cerrMessageBeforeThrow("void TXT::save(const char* fname)", "File could not be written.");
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
    const char thisFuncName[] = "Bitmap::Bitmap(const char* fname)";
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

            this->pixelAmount = (size_t)this->ih.Height * (size_t)this->ih.Width;
            this->bytesPerPixel = this->ih.BitsPerPixel >> 3;                   // -this->ih.BitsPerPixel >> 3 == this->ih.BitsPerPixel / 8

            this->data = new char[ih.SizeOfBitmap];
            file.read(this->data, ih.SizeOfBitmap);                            // -Initializing bitmap data

            this->img = new RGB*[this->ih.Height];                                          // -Building pixel matrix
            for(i = this->ih.Height - 1, j = 0; i >= 0; i--, j++) {
                this->img[j] = (RGB*)&this->data[3 * i * this->ih.Width];
            }
            while(fname[sz++] != 0) {}                                          // -Getting name size.
            this->name = new char[sz];
            for(i = 0; i < sz; i++) this->name[i] = fname[i];                         // -Copying name
            file.close();
        } else {
            file.close();
            cerrMessageBeforeThrow(thisFuncName, "Not a valid bitmap file.");
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        cerrMessageBeforeThrow(thisFuncName, "File could not be opened.");
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
    this->pixelAmount = bmp.pixelAmount;
    this->bytesPerPixel = bmp.bytesPerPixel;

    int i, j;                                                                   // -Initializing data.
    this->data = new char[bmp.ih.SizeOfBitmap];
    for(i = 0; i < (int)bmp.ih.SizeOfBitmap; i++) this->data[i] = bmp.data[i];

    this->img = new RGB*[bmp.ih.Height];
    for(i = this->ih.Height - 1, j = 0; i >= 0; i--, j++) {                     // -Building pixel array over this image
        this->img[j] = (RGB*)&this->data[3 * i * ih.Width];
    }

    size_t sz = 0;                                                              // Initializing name
    while(bmp.name[sz++] != 0) {}                                               // -Getting name size.
    name = new char[sz];
    for(i = 0; i < (int)sz; i++) name[i] = bmp.name[i];
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
            cerrMessageBeforeThrow(thisFuncName, "Not a valid bitmap file");
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        cerrMessageBeforeThrow(thisFuncName, "File could not be written");
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
        this->pixelAmount = bmp.pixelAmount;
        this->bytesPerPixel = bmp.bytesPerPixel;

        int i, j;                                                               // -Copying data.
        if(this->data != NULL) delete[] this->data;
        this->data = new char[bmp.ih.SizeOfBitmap];
        for(i = 0; i < (int)bmp.ih.SizeOfBitmap; i++) this->data[i] = bmp.data[i];

        if(this->img != NULL) delete[] this->img;                               // -Copying pixel matrix
        this->img = new RGB*[bmp.ih.Height];
        for(i = this->ih.Height - 1, j = 0; i >= 0; i--, j++) {                 // -Building pixel array over this image
            this->img[j] = (RGB*)&this->data[3 * i * ih.Width];
        }

        size_t sz = 0;
        while(bmp.name[sz++] != 0) {}                                           // -Getting name size.
        if(this->name != NULL) delete[] this->name;
        this->name = new char[sz];
        for(i = 0; i < (int)sz; i++) this->name[i] = bmp.name[i];               // -Copying name
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

bool Bitmap::operator == (const Bitmap &bmp) const{
    bool equal =
    this->fh.bm[0] == bmp.fh.bm[0] &&
    this->fh.bm[1] == bmp.fh.bm[1] &&
    this->fh.size  == bmp.fh.size  &&
    this->fh.reserved1 == bmp.fh.reserved1 &&
    this->fh.reserved2 == bmp.fh.reserved2 &&
    this->fh.offset    == bmp.fh.offset    &&
    this->ih.size      == bmp.ih.size      &&
    this->ih.Height    == bmp.ih.Height    &&
    this->ih.Width     == bmp.ih.Width     &&
    this->ih.Planes    == bmp.ih.Planes    &&
    this->ih.BitsPerPixel   == bmp.ih.BitsPerPixel &&
    this->ih.Compression    == bmp.ih.Compression  &&
    this->ih.SizeOfBitmap   == bmp.ih.SizeOfBitmap &&
    this->ih.HorzResolution == bmp.ih.HorzResolution &&
    this->ih.VertResolution == bmp.ih.VertResolution &&
    this->ih.ColorsUsed     == bmp.ih.ColorsUsed     &&
    this->ih.ColorsImportant== bmp.ih.ColorsImportant;

    if(!equal) return false;

    for(size_t i = 0; i < bmp.ih.SizeOfBitmap; i++)
        if(this->data[i] != bmp.data[i]) return false;

    return true;
}

bool Bitmap::operator != (const Bitmap &bmp) const{
    return !this->operator==(bmp);
}

uint8_t Bitmap::getPixelColor(int i, int j, ColorID CId)  const{
    if(i > this->ih.Height) i %= this->ih.Height;
    if(i < 0) (i = i % this->ih.Height) < 0 ? i += this->ih.Height: i;
    if(j > this->ih.Width) j %= this->ih.Width;
    if(j < 0) (j = j % this->ih.Width)  < 0 ? j += this->ih.Width : j;
    switch(CId){
        case Red:
            return this->img[i][j].red;
        case Green:
            return this->img[i][j].green;
        case Blue:
            return this->img[i][j].blue;
    }
    return this->img[i][j].red;                                                 // -Just to prevent a compiler warning from appearing
}

BitmapStatistics::BitmapStatistics(const BitmapStatistics& bmpSts): pbmp(bmpSts.pbmp){
    int i, j;
    if(bmpSts.pbmp == NULL) return;
    for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) {
        this->Average[i] = bmpSts.Average[i];
        this->Entropy[i] = bmpSts.Entropy[i];
        this->XiSquare[i]= bmpSts.XiSquare[i];
    }
    for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++){
        for(j = 0; j < DIRECTIONS_AMOUNT; j++) {
            this->Covariance [i][j]= bmpSts.Covariance[i][j];
            this->Variance   [i][j]= bmpSts.Variance[i][j];
            this->Correlation[i][j]= bmpSts.Correlation[i][j];
        }
    }
}

BitmapStatistics::BitmapStatistics(const Bitmap* pbmp_): pbmp(pbmp_) {
    int i,j;
    if(this->pbmp == NULL) return;
    this->setpixelValueFrequence();
    for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) {
        this->Average[i] = this->average(Bitmap::ColorID(i));
        this->Entropy[i] = this->entropy(Bitmap::ColorID(i));
        this->XiSquare[i]= this->xiSquare(Bitmap::ColorID(i));
    }
    for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++){
        for(j = 0; j < DIRECTIONS_AMOUNT; j++) {
            this->Covariance [i][j] = this->covariance( Bitmap::ColorID(i), Bitmap::Direction(j), 1);
            this->Variance   [i][j] = this->variance(   Bitmap::ColorID(i), Bitmap::Direction(j));
            this->Correlation[i][j] = this->correlation(Bitmap::ColorID(i), Bitmap::Direction(j), 1);
        }
    }
}

BitmapStatistics& BitmapStatistics::operator = (const BitmapStatistics& bmpSts){
    if(this != &bmpSts) {
        int i,j;
        this->pbmp = bmpSts.pbmp;
        for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) {
            this->Average[i] = bmpSts.Average[i];
            this->Entropy[i] = bmpSts.Entropy[i];
            this->XiSquare[i]= bmpSts.XiSquare[i];
        }
        for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++){
            for(j = 0; j < DIRECTIONS_AMOUNT; j++) {
                this->Covariance [i][j]= bmpSts.Covariance[i][j];
                this->Variance   [i][j]= bmpSts.Variance[i][j];
                this->Correlation[i][j]= bmpSts.Correlation[i][j];
            }
        }
    }
    return *this;
}

double BitmapStatistics::average(const Bitmap::ColorID CId) const{
    double average = 0.0;
    for(int i = 0, j; i < this->pbmp->ih.Height; i++)
        for(j = 0; j < this->pbmp->ih.Width; j++)
            average += (double)this->pbmp->getPixelColor(i,j,CId);
    average /= double(this->pbmp->pixelAmount);
    return average;
}

double BitmapStatistics::covariance(const Bitmap::ColorID CId, Bitmap::Direction dr, size_t offset) const{
    if(offset >= this->pbmp->pixelAmount) offset %= this->pbmp->pixelAmount;
    int i, j, k, l;
    const int h = this->pbmp->ih.Height, w = this->pbmp->ih.Width;
    const int h_offset = offset / (size_t)this->pbmp->ih.Width, w_offset = offset % (size_t)this->pbmp->ih.Width;
    double covariance = 0.0;
    const double avr = this->Average[CId] == -1.0 ? this->average(CId) : this->Average[CId];

    switch(dr){
        case Bitmap::horizontal:
            for(i = 0, k = h_offset; i < h; i++, k++){
                if(k == h) k = 0;
                for(j = 0, l = w_offset; j < w; j++, l++){
                    if(l == w) {
                        l = 0;
                        k++;
                        if(k == h) k = 0;
                    }
                    covariance += ((double)this->pbmp->getPixelColor(i, j, CId) - avr)*((double)this->pbmp->getPixelColor(k, l, CId) - avr);
                }
            }
            break;
        case Bitmap::vertical:
            for(j = 0, l = w_offset; j < w; j++, l++){
                if(l == w) l = 0;
                for(i = 0, k = h_offset; i < h; i++, k++){
                    if(k == h) {
                        k = 0;
                        l++;
                        if(l == w) l = 0;
                    }
                    covariance += ((double)this->pbmp->getPixelColor(i, j, CId) - avr)*((double)this->pbmp->getPixelColor(k, l, CId) - avr);
                }
            }
            break;
    }
    covariance /= (double)(this->pbmp->pixelAmount);
    return covariance;
}

double BitmapStatistics::variance(const Bitmap::ColorID CId, Bitmap::Direction dr) const{
    return this->covariance(CId, dr, 0);
}

double BitmapStatistics::correlation(const Bitmap::ColorID CId, Bitmap::Direction dr, size_t offset) const{
    if(this->Variance[CId][dr] == -1.0) return this->covariance(CId, dr, offset) / this->variance(CId, dr);
    return this->Covariance[CId][dr] / this->Variance[CId][dr];
}

void BitmapStatistics::setpixelValueFrequence(){
    int i = 0, j=  0;
    if(!this->pixelValueFrequenceStablished) {
        for(i = 0; i < this->pbmp->ih.Height; i++)
            for(j = 0; j < this->pbmp->ih.Width; j++) {
                this->pixelValueFrequence[Bitmap::ColorID::Red][this->pbmp->getPixelColor(i, j, Bitmap::ColorID::Red)]++;
                this->pixelValueFrequence[Bitmap::ColorID::Green][this->pbmp->getPixelColor(i, j, Bitmap::ColorID::Green)]++;
                this->pixelValueFrequence[Bitmap::ColorID::Blue][this->pbmp->getPixelColor(i, j, Bitmap::ColorID::Blue)]++;
        }
        this->pixelValueFrequenceStablished = true;
    }
}

double BitmapStatistics::entropy(const Bitmap::ColorID color) const{
    double  entropy =  0.0 ;
    double  p[256]  = {0.0};
    double  sz      = (double)this->pbmp->ih.Height*(double)this->pbmp->ih.Width;
    int     i = 0;

    for(i = 0; i < 256; i++) p[i] = this->pixelValueFrequence[color][i]/sz;
    for(i = 0; i < 256; i++) if(p[i] != 0) entropy -= p[i]*log2(p[i]);

    return entropy;
}

double BitmapStatistics::xiSquare(const Bitmap::ColorID color) const{
    double  xiSquare=  0.0 ;
    double  sz      = (double)this->pbmp->ih.Height*(double)this->pbmp->ih.Width;
    int     i = 0;

    for(i = 0; i < 256; i++)
        xiSquare += (double)(this->pixelValueFrequence[color][i]*this->pixelValueFrequence[color][i]);
    xiSquare *= 256.0/sz; xiSquare -= sz;

    return xiSquare;
}

static std::ostream& fixedLengthNumber(std::ostream& os, const double n, size_t len){
    double    abs_n = (n < 0.0 ? -n : n);                                       // -Guarding against exception with log10
    const int log_n = (abs_n == 0.0 ? -1 : log10(abs_n));                       // -This will tell us the number of digits in the integral part
    const int intPartdigitsAmoutn = log_n + 1;                                  // -Amount of digits in the integral part
    long long intPart_n = (long long)abs_n;                                     // -Saving the integral part
    double    aux;

    if(len > 308) len = 308;                                                    // -Maximum number of digits for a double
    if(len == 0)  return os;
    if((int)len < intPartdigitsAmoutn) len = (size_t)intPartdigitsAmoutn;       // -We will sent at least the integer part
    if(n < 0) os << '-';                                                        // -Considering the sign not as part of the number
    if(intPartdigitsAmoutn >= 1){
        os << intPart_n;                                                        // -Sending the integer part.
        abs_n -= (double)intPart_n;                                             // -Taking out the integral part.
        if((len -= (size_t)intPartdigitsAmoutn) == 0) return os;
    } else {
        os << '0';                                                              // -There is no integral part, just decimals after the point.
        if((--len) == 0) return os;
    }
    os << '.';
    abs_n *= 10, intPart_n = (long long)abs_n;
    while(intPart_n == 0 && len > 0){                                           // -Considering the decimal part as a integer number, sending the left
        os << '0';                                                              //  zeros of it
        len--;
        abs_n *= 10;
        intPart_n = (long long)abs_n;
    }
    for(aux = abs_n; len > 0; len--) {                                          // Passing the decimal part to the integral part
        aux *= 10.0;
        if(aux >= (double)(uint64_t)0xFFFFFFFFFFFFFFFF){                        // Guarding against overflow
            intPart_n = (long long)abs_n;                                       // Returning one digit
            os << intPart_n;                                                    // Sending integer part
            abs_n -= (double)intPart_n;
            aux = abs_n;
            len++;
        } else abs_n = aux;
    }
    os << (long long)abs_n;
    return os;
}

std::ostream& File::operator << (std::ostream& os, const BitmapStatistics& bmSt){
    int i;
    os << "              \tRed\t\tGreen\t\tBlue\n";
    os << "Entropy      :\t"; for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) os << bmSt.Entropy[i] << "\t\t"; os << '\n';
    os << "Xi Square    :\t"; for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) os << bmSt.XiSquare[i] << "\t\t"; os << '\n';
    os << "Correlation" << '\n';
    os << "Horizontal   :\t"; for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) fixedLengthNumber(os, bmSt.Correlation[i][0], 7) << "\t"; os << '\n';
    os << "Vertical     :\t"; for(i = 0; i < PIXEL_COMPONENTS_AMOUNT; i++) fixedLengthNumber(os, bmSt.Correlation[i][1], 7) << "\t"; os << '\n';

    return os;
}
