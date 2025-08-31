#include"../include/bitmap.hpp"
#include<fstream>
#include<cstring>
#include<cmath>
#include<exception>

const char*const Bitmap::RGBlabels[(unsigned)RGB::Color_amount] = {"Red", "Green", "Blue"};
const char*const Bitmap::DirectionLabels[(unsigned)Direction::direction_amount] = {"Horizontal", "Vertical", "Diagonal"};

Bitmap::Bitmap(const std::filesystem::path& path) : FileBase(path){
    std::ifstream file;
    file.open(path, std::ios::binary);
    int i, j, sz = 0;
    if(file.is_open()) {
        file.read((char*)this->fh.bm, 2);
        if(this->fh.bm[0] == 'B' && this->fh.bm[1] == 'M') {
            // -File Header.
            file.read((char*)&this->fh.size, 4);
            file.read((char*)&this->fh.reserved1, 2);
            file.read((char*)&this->fh.reserved2, 2);
            file.read((char*)&this->fh.offset, 4);

            // -Image Header.
            file.read((char*)&this->ih.size, 4);
            file.read((char*)&this->ih.Width, 4);
            file.read((char*)&this->ih.Height, 4);
            file.read((char*)&this->ih.Planes, 2);
            file.read((char*)&this->ih.BitsPerPixel, 2);
            file.read((char*)&this->ih.Compression, 4);
            file.read((char*)&this->ih.SizeOfBitmap, 4);
            file.read((char*)&this->ih.HorzResolution, 4);
            file.read((char*)&this->ih.VertResolution, 4);
            file.read((char*)&this->ih.ColorsUsed, 4);
            file.read((char*)&this->ih.ColorsImportant, 4);
            this->pixelAmount = (size_t)this->ih.Height * (size_t)this->ih.Width;
            this->bytesPerPixel = this->ih.BitsPerPixel / 8;
            this->widthInBytes = this->ih.Width*this->bytesPerPixel;
            file.close();
        } else {
            file.close();
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throw std::runtime_error("File could not be opened.");
    }
}

bool Bitmap::load(){
    std::ifstream file;
    file.open(this->file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file.seekg(this->fh.offset);
    this->data.resize(ih.SizeOfBitmap);
    if(file.read(reinterpret_cast<char*>(this->data.data()), ih.SizeOfBitmap)){ // -Initializing bitmap data
        return true;
    }
    this->data.clear();                                                         // Clear data on failure
    return false;
}

Bitmap::Bitmap(const Bitmap& bmp) : FileBase(bmp){
    this->fh.bm[0] = bmp.fh.bm[0];                                              // -Initializing file header.
    this->fh.bm[1] = bmp.fh.bm[1];                                              // ...
    this->fh.size = bmp.fh.size;                                                // ...
    this->fh.reserved1 = bmp.fh.reserved1;                                      // ...
    this->fh.reserved2 = bmp.fh.reserved2;                                      // ...
    this->fh.offset = bmp.fh.offset;                                            // ...

    this->ih = bmp.ih;                                                          // -Initializing image header. Using the default member to member copy.

    this->pixelAmount = bmp.pixelAmount;
    this->bytesPerPixel = bmp.bytesPerPixel;
    this->widthInBytes = bmp.widthInBytes;

    this->data = bmp.data;
}

bool Bitmap::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    file.open(output_path, std::ios::binary);
    if(file.is_open()) {
        if(this->fh.bm[0] == 'B' && this->fh.bm[1] == 'M') {
            uint32_t updatedOffset = sizeof(FileHeader) + sizeof(ImageHeader);
            uint32_t updatedFileSize = this->ih.SizeOfBitmap + updatedOffset;
            file.write((char*)this->fh.bm, 2);                                        // -File Header.
            file.write((char*)&updatedFileSize, 4);                             // ...
            file.write((char*)&this->fh.reserved1, 2);                                // ...
            file.write((char*)&this->fh.reserved2, 2);                                // ...
            file.write((char*)&updatedOffset, 4);                               // ...

            file.write((char*)&this->ih.size, 4);                                     // -Image Header.
            file.write((char*)&this->ih.Width, 4);                                    // ...
            file.write((char*)&this->ih.Height, 4);                                   // ...
            file.write((char*)&this->ih.Planes, 2);                                   // ...
            file.write((char*)&this->ih.BitsPerPixel, 2);                             // ...
            file.write((char*)&this->ih.Compression, 4);                              // ...
            file.write((char*)&this->ih.SizeOfBitmap, 4);                             // ...
            file.write((char*)&this->ih.HorzResolution, 4);                           // ...
            file.write((char*)&this->ih.VertResolution, 4);                           // ...
            file.write((char*)&this->ih.ColorsUsed, 4);                               // ...
            file.write((char*)&this->ih.ColorsImportant, 4);                          // ...
            file.write((char*)this->data.data(), ih.SizeOfBitmap);                           // ...
            file.close();
        } else {
            file.close();
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throw std::runtime_error("File could not be written.");
    }
    return true;
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
        this->widthInBytes = bmp.widthInBytes;
    }
    return *this;
}

std::ostream& operator << (std::ostream &stream, const Bitmap &bmp) {
    stream << "File path:";
    stream << "\n\t" << bmp.file_path;
    stream << "\nFile Header: ";
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

    return this->data == bmp.data;
}

bool Bitmap::operator != (const Bitmap &bmp) const{
    return !this->operator==(bmp);
}

uint8_t Bitmap::getPixelComponentValue(size_t i, size_t j, RGB c)  const{
    if(i > this->ih.Height) i %= this->ih.Height;
    if(j > this->ih.Width) j %= this->ih.Width;
    return this->data[i*this->widthInBytes + j*this->bytesPerPixel + (unsigned)c]; // -Just to prevent a compiler warning from appearing
}

/******************************************************************************************************************************************************************
                                                                        BitmapStatistics
******************************************************************************************************************************************************************/

/*BitmapStatistics::BitmapStatistics(const BitmapStatistics& bmpSts): pbmp(bmpSts.pbmp){
    int i, j;
    if(bmpSts.pbmp == NULL) return;
    this->histogramStablished = bmpSts.histogramStablished;
    for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) {
        this->Average[i] = bmpSts.Average[i];
        this->Entropy[i] = bmpSts.Entropy[i];
        this->XiSquare[i]= bmpSts.XiSquare[i];
        for(j = 0; j < 256; j++) this->histogram[i][j] = bmpSts.histogram[i][j];
    }
    for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++){
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
    this->sethistogram();
    for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) {
        this->Average[i] = this->average(Bitmap::ColorID(i));
        this->Entropy[i] = this->entropy(Bitmap::ColorID(i));
        this->XiSquare[i]= this->xiSquare(Bitmap::ColorID(i));
    }
    for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++){
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
        this->histogramStablished = bmpSts.histogramStablished;
        for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) {
            this->Average[i] = bmpSts.Average[i];
            this->Entropy[i] = bmpSts.Entropy[i];
            this->XiSquare[i]= bmpSts.XiSquare[i];
            for(j = 0; j < 256; j++) this->histogram[i][j] = bmpSts.histogram[i][j];
        }
        for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++){
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
    int i, j, k, l, r;                                                          // -(i,j) is the first point and (k,l) is the second point
    const int h = this->pbmp->ih.Height, w = this->pbmp->ih.Width;
    int vertical_offset;                                                        // -Looking offset as a point in the matrix that represents the image. Using
    int horizontal_offset;                                                      //  division algorithm offset = vertical_offset*w + horizontal offset
    double covariance = 0.0;
    const double avr = this->Average[CId] == -1.0 ? this->average(CId) : this->Average[CId];// -Pixel-color values are nonnegative, so avr >= 0.

    switch(dr){
        case Bitmap::horizontal:
            vertical_offset = (int)offset / w;
            horizontal_offset = (int)offset % w;
            for(i = 0, k = vertical_offset; i < h; i++, k++){
                if(k == h) k = 0;
                for(j = 0, l = horizontal_offset; j < w; j++, l++){
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
            vertical_offset = (int)offset % h;
            horizontal_offset = (int)offset / h;
            for(j = 0, l = horizontal_offset; j < w; j++, l++){
                if(l == w) l = 0;
                for(i = 0, k = vertical_offset; i < h; i++, k++){
                    if(k == h) {
                        k = 0;
                        l++;
                        if(l == w) l = 0;
                    }
                    covariance += ((double)this->pbmp->getPixelColor(i, j, CId) - avr)*((double)this->pbmp->getPixelColor(k, l, CId) - avr);
                }
            }
            break;
        case Bitmap::diagonal:
            vertical_offset = (int)offset % h;
            horizontal_offset = (int)offset % w;
            for(r = w-1; r >= 0; r--){
                for(i = 0, j = r, k = vertical_offset, l = horizontal_offset + r; j < w; i++, j++, k++, l++) {
                    if(i == h) break;
                    if(k == h) k = 0;
                    if(l == w) l = 0;
                    covariance += ((double)this->pbmp->getPixelColor(i, j, CId) - avr)*((double)this->pbmp->getPixelColor(k, l, CId) - avr);
                }
            }
            for(r = 1; r < h; r++){
                for(i = r, j = 0, k = vertical_offset + r, l = horizontal_offset; i < h; i++, j++, k++, l++) {
                    if(j == w) break;
                    if(k == h) k = 0;
                    if(l == w) l = 0;
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

void BitmapStatistics::sethistogram(){
    int i = 0, j=  0;
    if(!this->histogramStablished) {
        for(i = 0; i < this->pbmp->ih.Height; i++)
            for(j = 0; j < this->pbmp->ih.Width; j++) {
                this->histogram[Bitmap::ColorID::Red][this->pbmp->getPixelColor(i, j, Bitmap::ColorID::Red)]++;
                this->histogram[Bitmap::ColorID::Green][this->pbmp->getPixelColor(i, j, Bitmap::ColorID::Green)]++;
                this->histogram[Bitmap::ColorID::Blue][this->pbmp->getPixelColor(i, j, Bitmap::ColorID::Blue)]++;
        }
        this->histogramStablished = true;
    }
}

double BitmapStatistics::entropy(const Bitmap::ColorID color) const{
    double  entropy =  0.0 ;
    double  p[256]  = {0.0};
    double  sz      = (double)this->pbmp->ih.Height*(double)this->pbmp->ih.Width;
    int     i = 0;

    for(i = 0; i < 256; i++) p[i] = this->histogram[color][i]/sz;
    for(i = 0; i < 256; i++) if(p[i] != 0) entropy -= p[i]*log2(p[i]);

    return entropy;
}

double BitmapStatistics::xiSquare(const Bitmap::ColorID color) const{
    double  xiSquare=  0.0 ;
    double  sz      = (double)this->pbmp->ih.Height*(double)this->pbmp->ih.Width;
    int     i = 0;

    for(i = 0; i < 256; i++)
        xiSquare += (double)(this->histogram[color][i]*this->histogram[color][i]);
    xiSquare *= 256.0/sz; xiSquare -= sz;

    return xiSquare;
}

double BitmapStatistics::retreaveCorrelation(const Bitmap::ColorID CID, Bitmap::Direction dr, double* xAxis_dest, double* yAxis_dest) const{
    int i, j, k, l, r, c;                                                       // -(i,j) is the first point and (k,l) is the second point
    const int h = this->pbmp->ih.Height, w = this->pbmp->ih.Width;
    int vertical_offset;                                                        // -Looking offset as a point in the matrix that represents the image. Using
    int horizontal_offset;                                                      //  division algorithm offset = vertical_offset*w + horizontal offset

    if(xAxis_dest != NULL && yAxis_dest != NULL) {
        switch(dr){
            case Bitmap::horizontal:
                vertical_offset = 0;
                horizontal_offset = 1;
                for(i = 0, c = 0, k = vertical_offset; i < h; i++, k++){
                    if(k == h) k = 0;
                    for(j = 0, l = horizontal_offset; j < w; j++, l++, c++){
                        if(l == w) {
                            l = 0;
                            k++;
                            if(k == h) k = 0;
                        }
                        xAxis_dest[c] = (double)this->pbmp->getPixelColor(i, j, CID);
                        yAxis_dest[c] = (double)this->pbmp->getPixelColor(k, l, CID);
                    }
                }
                break;
            case Bitmap::vertical:
                vertical_offset = 1;
                horizontal_offset = 0;
                for(j = 0, c = 0, l = horizontal_offset; j < w; j++, l++){
                    if(l == w) l = 0;
                    for(i = 0, k = vertical_offset; i < h; i++, k++, c++){
                        if(k == h) {
                            k = 0;
                            l++;
                            if(l == w) l = 0;
                        }
                        xAxis_dest[c] = (double)this->pbmp->getPixelColor(i, j, CID);
                        yAxis_dest[c] = (double)this->pbmp->getPixelColor(k, l, CID);
                    }
                }
                break;
            case Bitmap::diagonal:
                vertical_offset = 1;
                horizontal_offset = 1;
                for(r = w-1, c = 0; r >= 0; r--){
                    for(i = 0, j = r, k = vertical_offset, l = horizontal_offset + r; j < w; i++, j++, k++, l++, c++) {
                        if(i == h) break;
                        if(k == h) k = 0;
                        if(l == w) l = 0;
                        xAxis_dest[c] = (double)this->pbmp->getPixelColor(i, j, CID);
                        yAxis_dest[c] = (double)this->pbmp->getPixelColor(k, l, CID);
                    }
                }
                for(r = 1; r < h; r++){
                    for(i = r, j = 0, k = vertical_offset + r, l = horizontal_offset; i < h; i++, j++, k++, l++, c++) {
                        if(j == w) break;
                        if(k == h) k = 0;
                        if(l == w) l = 0;
                        xAxis_dest[c] = (double)this->pbmp->getPixelColor(i, j, CID);
                        yAxis_dest[c] = (double)this->pbmp->getPixelColor(k, l, CID);
                    }
                }
                break;
        }
    }
    return this->Correlation[CID][dr];
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
    os << "Entropy      :\t"; for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) os << bmSt.Entropy[i] << "\t\t"; os << '\n';
    os << "Xi Square    :\t"; for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) os << bmSt.XiSquare[i] << "\t\t"; os << '\n';
    os << "Correlation" << '\n';
    os << "Horizontal   :\t"; for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) fixedLengthNumber(os, bmSt.Correlation[i][0], 7) << "\t"; os << '\n';
    os << "Vertical     :\t"; for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) fixedLengthNumber(os, bmSt.Correlation[i][1], 7) << "\t"; os << '\n';
    os << "Diagonal     :\t"; for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++) fixedLengthNumber(os, bmSt.Correlation[i][2], 7) << "\t"; os << '\n';

    return os;
}*/
