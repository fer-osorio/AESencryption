// -Set of structures representing files. The intention is to handle files for its encryption
#ifndef _INCLUDED_FILE_
#define _INCLUDED_FILE_

#include"file_base.hpp"

namespace File {

//#define NAME_MAX_LEN 4096

class Bitmap;									// -The intention is to use the name Bitmap in the next function
std::ostream& operator << (std::ostream& st, const Bitmap& bmp);		// -What we want is to make this function visible inside the name space scope
class Bitmap : public FileBase {							// -Handling bitmap format images.
public:
	enum struct RGB{ Red, Green, Blue, Color_amount};
	enum struct Direction{ horizontal, vertical, diagonal, direction_amount };
	static const char*const RGBlabels[static_cast<unsigned>(RGB::Color_amount)];
	static const char*const DirectionLabels[static_cast<unsigned>(Direction::direction_amount)];
private:
	struct RGBcolor {
		uint8_t red;
		uint8_t green;
		uint8_t blue;
	};

	#pragma pack(push,1)							// BMP format requires no padding
	struct FileHeader {
		char     bm[2];							// [B, M] for bmp files
		unsigned size;  						// File size
		uint16_t reserved1;						// Dependent on the originator application
		uint16_t reserved2;						// Dependent on the originator application
		uint32_t offset;						// Starting address of the image data
	} fh = {0,0,0,0,0,0};

	struct ImageHeader {
		uint32_t size;							// Size of this header
		int 	 Width;							// Image width in pixels
		int	 Height;						// Image height in pixels
		uint16_t Planes;						// Number of color planes (must be 1)
		uint16_t BitsPerPixel;						// Number of bits per pixel, in this case 24
		uint32_t Compression;						// Compression method
		uint32_t SizeOfBitmap;						// Size of raw bitmap data
		int	 HorzResolution; 					// Horizontal pixel per meter
		int	 VertResolution; 					// Vertical pixel per meter
		uint32_t ColorsUsed;						// Colors in the color palette, 0 to default
		uint32_t ColorsImportant;					// Zero when every color is important
	} ih = {0,0,0,0,0,0,0,0,0,0,0};
	#pragma pack(pop)

	size_t pixelAmount;
	size_t bytesPerPixel;
	size_t widthInBytes;

public:
	explicit Bitmap(const std::filesystem::path& path);
	Bitmap(const Bitmap& bmp);

	bool load() override;
	bool save(const std::filesystem::path& output_path) const override;

	Bitmap& operator = (const Bitmap& bmp);
	friend std::ostream& operator << (std::ostream& st, const Bitmap& bmp);

	bool operator == (const Bitmap& bmp) const;
	bool operator != (const Bitmap& bmp) const;

	size_t PixelAmount() const{ return this->pixelAmount; }
	size_t dataSize() const{ return this->ih.SizeOfBitmap; }
private:
	uint8_t getPixelComponentValue(size_t i, size_t j, RGB c) const;
};

} // namespace File

#endif