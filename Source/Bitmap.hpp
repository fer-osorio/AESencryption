// -Handling bitmap format images.
#include <iostream>
#include <stdlib.h>
#include "AES_256.hpp"

typedef unsigned char  ui08;
typedef unsigned short ui16;
typedef unsigned int   ui32;

struct RGB {
	ui08 red;
	ui08 green;
	ui08 blue;
};

class Bitmap {
	struct FileHeader {
		char bm[2];			// [B, M] for bmp files
		unsigned size;  	// File size
		ui16 reserved1;		// Dependent on the originator application
		ui16 reserved2;		// Dependent on the originator application
		ui32 offset;		// Starting address of the image data
	} fh ;

	struct ImageHeader {
		ui32 size;				// Size of this header
		int Width;				// Image width in pixels
		int Height;				// Image height in pixels
		ui16 Planes;			// Number of color planes (must be 1)
		ui16 BitsPerPixel;		// Number of bits per pixel, in this case 24
		ui32 Compression;		// Compression method
		ui32 SizeOfBitmap;		// Size of raw bitmap data
		int HorzResolution; 	// Horizontal pixel per meter
		int VertResolution; 	// Vertical pixel per meter
		ui32 ColorsUsed;		// Colors in the color palette, 0 to default
		ui32 ColorsImportant;	// Zero when every color is important
	} ih ;

	char* data;
	RGB** img;

	public:
	Bitmap(const char* fname);
	void save(const char* fname);
	~Bitmap();

	// -This function will allow us to encrypt
	//  several images with just one AES_256
	//  object.
	friend void encrypt(Bitmap bmp, AES_256 e);

	friend std::ostream& operator << (std::ostream& st, const Bitmap& bmp);
};
