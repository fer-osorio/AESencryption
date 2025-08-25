#include"valid_file_path.hpp"
#include<iostream>
#include<cstring>

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
        std::cerr << "In file Source/File.cpp, function static FileExtensions getExtension(const char fileName[]). filename == NULL...\n";
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
