// -Handling bitmap format images.

#ifndef _INCLUDED_FILE_
#define _INCLUDED_FILE_

#include "raster_image.hpp"

namespace File {

class Bitmap;									// -Forward declaration. Intention is to use Bitmap name in output stream function
std::ostream& operator << (std::ostream& st, const Bitmap& bmp);		// -What we want is to make this function visible inside the name space scope

class Bitmap : public RasterImage {
public:
	enum struct RGB{ Red, Green, Blue, Color_amount};
	enum struct Direction{ horizontal, vertical, diagonal, direction_amount };
	static const char*const RGBlabels[static_cast<unsigned>(RGB::Color_amount)];
	static const char*const DirectionLabels[static_cast<unsigned>(Direction::direction_amount)];

	struct RGBcolor {
		uint8_t red;
		uint8_t green;
		uint8_t blue;
	};

public:
	explicit Bitmap(const std::filesystem::path& path);
	Bitmap(const Bitmap& bmp);

	void save(const std::filesystem::path& output_path = "") const override;

	Bitmap& operator = (const Bitmap& bmp);
	friend std::ostream& operator << (std::ostream& st, const Bitmap& bmp);

	bool operator == (const Bitmap& bmp) const;
	bool operator != (const Bitmap& bmp) const;

	size_t PixelAmount() const { return static_cast<size_t>(width_) * static_cast<size_t>(height_); }
	size_t dataSize() const { return this->data.size(); }
private:
	uint8_t getPixelComponentValue(size_t i, size_t j, RGB c) const;
};

} // namespace File

#endif
