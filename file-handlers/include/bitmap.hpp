// -Set of structures representing files. The intention is to handle files for its encryption
#ifndef _INCLUDED_FILE_
#define _INCLUDED_FILE_

#include"file_base.hpp"
#include"../../include/cipher.hpp"

//#define NAME_MAX_LEN 4096

class Bitmap;									// -The intention is to use the name Bitmap in the next function
std::ostream& operator << (std::ostream& st, const Bitmap& bmp);		// -What we want is to make this function visible inside the name space scope
class Bitmap : FileBase {							// -Handling bitmap format images.
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

/*std::ostream& operator << (std::ostream& os, const BitmapStatistics& bmSt);
struct BitmapStatistics{
	private:
	const  Bitmap* 	  pbmp		= NULL;
	double Average    [RGB_COMPONENTS_AMOUNT]  = {-1.0};
	double Covariance [RGB_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT]  = {{ 0.0, 0.0, 0.0},{ 0.0, 0.0, 0.0},{ 0.0, 0.0, 0.0}};
	double Variance   [RGB_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT]  = {{-1.0,-1.0,-1.0},{-1.0,-1.0,-1.0},{-1.0,-1.0,-1.0}};
	double Correlation[RGB_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT]  = {{10.0,10.0,10.0},{10.0,10.0,10.0},{10.0,10.0,10.0}};

	uint32_t histogram[RGB_COMPONENTS_AMOUNT][256] = {{0},{0},{0}};
	bool	 histogramStablished = false;

	double Entropy    [RGB_COMPONENTS_AMOUNT]  = { 0.0};
	double XiSquare   [RGB_COMPONENTS_AMOUNT]  = { 0.0};

	double average(    const Bitmap::RGB) const;			// -Average value of color in a range of pixels. Horizontal calculation
	double covariance( const Bitmap::RGB, Bitmap::Direction dr, size_t offset) const;
	double variance(   const Bitmap::RGB, Bitmap::Direction dr) const;
	double correlation(const Bitmap::RGB, Bitmap::Direction dr, size_t offset) const;
	double entropy(const Bitmap::RGB) const;
	double xiSquare(const Bitmap::RGB)const;

	void sethistogram();

	public:
	BitmapStatistics() {}
	BitmapStatistics(const BitmapStatistics&);
	BitmapStatistics(const Bitmap* pbmp_);
	BitmapStatistics& operator = (const BitmapStatistics&);

	double retreaveCorrelation(const Bitmap::RGB CID, Bitmap::Direction dr, double* xAxis_dest = NULL, double* yAxis_dest = NULL) const;
	double retreaveEntropy(const Bitmap::RGB CID) const{ return this->Entropy[CID]; }
	double retreaveXiSquare(const Bitmap::RGB CID) const{ return this->XiSquare[CID]; }
	size_t pixelAmount() const{ return this->pbmp->PixelAmount(); }
	void   writeHistogram(Bitmap::RGB CID, double destination[]) const{ for(int i = 0; i < 256; i++) destination[i] = this->histogram[CID][i]; }

	friend std::ostream& operator << (std::ostream& os, const BitmapStatistics& bmSt);
	void writeBmpName(char destination[]) const{ this->pbmp->writeBmpName(destination); }
};*/
#endif