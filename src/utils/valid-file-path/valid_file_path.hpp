#include<stddef.h>

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
