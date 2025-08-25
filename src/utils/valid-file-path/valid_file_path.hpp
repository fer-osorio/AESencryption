#include<stddef.h>

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

Sld	->	l·Sld	| l·d·Sld	|	l	|	l·d		// -Concatenation of letters and digits that always start with a letter
Sled->	l·SPACES·Sled	| l·d·SPACES·Sled	|	l	|	l·d	// -Concatenation of letters and digits that always start with a letter

FN	->	Sld·FN	|	l						// -File Name can not start with a digit; a single letter can be a File Name
FN	->	.Sld·FN |	FN.Sld·FN	|	.Sld			// -Can not finish with a point nor have two consecutive points

FN  ->  "FNWE"                                                                  // -If double quotes are presented at the beginning of the string, the grammar
FNWE->	Sled·FN	|	l							//  accepts spaces in the middle of the string until the next double quote is found
FNWE->	.Sled·FN|	FN.Sled·FN	|	.Sled

FN  ->  FN/·Sld·FN   |   ../FN	|	/·Sld·FN				// -Considering file paths (Absolute Paths and Relative Paths) as file names

Note: SPACES can be represented by single spaces, or a concatenation of spaces
*/


struct StringFileNameAnalize {
	public:	enum Extension { bmp, txt, NoExtension, Unrecognized };
	private:static const Extension  SupportedExtension[2];
	private:static const size_t	SupportedExtensionAmount;
	private:static const char* 	SupportedExtensionString[2];
	private:static const size_t 	extensionStringAmount;
	private:
	enum CharType {zero, letter, digit, dot, underscore, hyphen, slash, space, singleQuote ,doubleQuote, notAllowed};

	const char* str = NULL;
	size_t      size = 0;
	unsigned    currentIndex = 0;

	static	CharType characterType(const char c);				// -True for the character that may appear in the file name, false in other case
	void 	cerrSyntaxErrMsg(const char[]);

	bool Sld();								// -The returned bool flags the founding of zero byte or the characters '\'' or '"')
	bool FN ();

	StringFileNameAnalize(const char str_[]);

	public:
	static Extension getExtension(const char[]);				// -Compares its input with the strings in supportedExtension array
	static bool isValidFileName(const char str[]);
};
