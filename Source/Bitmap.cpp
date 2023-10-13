#include <fstream>
#include "Bitmap.hpp"

#ifndef _INCLUDED_BITMAP_
#define _INCLUDED_BITMAP_

Bitmap::Bitmap(const char* fname) : data(NULL), img(NULL) {
    std::ifstream file;
    file.open(fname, std::ios::binary);
    int i, j;
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

            // Bitmap data
            file.read((char*)data, ih.SizeOfBitmap);

            // Pixel matrix
            img = new RGB*[ih.Height];
            for(i = ih.Height - 1, j = 0; i >= 0; i--, j++) {
                img[j] = (RGB*)&data[3 * i * ih.Width];
            }
        } else {
            throw "Not a valid bitmap file.";
        }
    } else {
        throw "File could not be opened/created.";
    }
}

void Bitmap::save(const char *fname) {
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.write((char*)fh.bm, 2);
        if(fh.bm[0] == 'B' && fh.bm[1] == 'M') {
            // -File Header.
            file.write((char*)&fh.size, 4);
            file.write((char*)&fh.reserved1, 2);
            file.write((char*)&fh.reserved2, 2);
            file.write((char*)&fh.offset, 4);

            // -Image Header.
            file.write((char*)&ih.size, 4);
            file.write((char*)&ih.Width, 4);
            file.write((char*)&ih.Height, 4);
            file.write((char*)&ih.Planes, 2);
            file.write((char*)&ih.BitsPerPixel, 2);
            file.write((char*)&ih.Compression, 4);
            file.write((char*)&ih.SizeOfBitmap, 4);
            file.write((char*)&ih.HorzResolution, 4);
            file.write((char*)&ih.VertResolution, 4);
            file.write((char*)&ih.ColorsUsed, 4);
            file.write((char*)&ih.ColorsImportant, 4);
            file.write((char*)data, ih.SizeOfBitmap);
        } else {
            throw "Not a valid bitmap file.";
        }
    } else {
        throw "File could not be written.";
    }
}

Bitmap::~Bitmap() {
    if(data != NULL) delete[] data;
    if(img  != NULL) delete[] img;
}

void encrypt(Bitmap bmp, AES_256 e) {
    e.encryptCBC(bmp.data, bmp.ih.SizeOfBitmap);
    bmp.save("Encryption.bmp");
}

std::ostream& operator << (std::ostream &stream, const Bitmap &bmp) {
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

#endif
