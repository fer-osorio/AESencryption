#include <fstream>
#include "Bitmap.hpp"

#ifndef _INCLUDED_BITMAP_
#define _INCLUDED_BITMAP_

Bitmap::Bitmap(const char* fname) {
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
            data = new char[ih.SizeOfBitmap];

            // Bitmap data
            file.read((char*)data, ih.SizeOfBitmap);

            // Pixel matrix
            img = new RGB*[ih.Height];
            for(i = ih.Height - 1, j = 0; i >= 0; i--, j++) {
                img[j] = (RGB*)&data[3 * i * ih.Width];
            }
            // Name
            while(fname[sz++] != 0) {} // -Getting name size.
            name = new char[sz];
            for(i = 0; i < sz; i++) name[i] = fname[i];
        } else {
            throw "Not a valid bitmap file.";
        }
    } else {
        throw "File could not be opened/created.";
    }
}

Bitmap::Bitmap(const Bitmap& bmp) {
    // Initializing file header.
    this->fh.bm[0] = bmp.fh.bm[0];
    this->fh.bm[1] = bmp.fh.bm[1];
    this->fh.size = bmp.fh.size;
    this->fh.reserved1 = bmp.fh.reserved1;
    this->fh.reserved2 = bmp.fh.reserved2;
    this->fh.offset = bmp.fh.offset;

    // -Initializing image header.
    // -Using the default member
    //  to member copy.
    this->ih = bmp.ih;

    ui32 i; // -Initializing data.
    this->data = new char[bmp.ih.SizeOfBitmap];
    for(i = 0; i < bmp.ih.SizeOfBitmap; i++) this->data[i] = bmp.data[i];

    this->img = new RGB*[bmp.ih.Height];
    for(i = 0; (int)i < bmp.ih.Height; i++) this->img[i] = bmp.img[i];

    ui32 sz = 0; // Initializing name
    while(bmp.name[sz++] != 0) {} // -Getting name size.
    name = new char[sz];
    for(i = 0; i < sz; i++) name[i] = bmp.name[i];
}

Bitmap::~Bitmap() {
    if(data != NULL) {
        delete[] data;
        data = NULL;
    }
    if(img  != NULL) {
        delete[] img;
        img = NULL;
    }
    if(name != NULL) {
        delete[] name;
        name = NULL;
    }
}

void Bitmap::save(const char *fname) {
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        if(fh.bm[0] == 'B' && fh.bm[1] == 'M') {
            // -File Header.
            file.write((char*)fh.bm, 2);
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
            file.close();
        } else {
            file.close();
            throw "Not a valid bitmap file.";
        }
    } else {
        throw "File could not be written.";
    }
}

Bitmap& Bitmap::operator = (const Bitmap &bmp) {
    if(this != &bmp) { // Guarding against bmp = bmp
        this->~Bitmap();
        // Copying file header.
        this->fh.bm[0] = bmp.fh.bm[0];
        this->fh.bm[1] = bmp.fh.bm[1];
        this->fh.size = bmp.fh.size;
        this->fh.reserved1 = bmp.fh.reserved1;
        this->fh.reserved2 = bmp.fh.reserved2;
        this->fh.offset = bmp.fh.offset;

        // -Copying image header.
        // -Using the default member
        //  to member copy.
        this->ih = bmp.ih;

        ui32 i; // -Copying data.
        this->data = new char[bmp.ih.SizeOfBitmap];
        for(i = 0; i < bmp.ih.SizeOfBitmap; i++) this->data[i] = bmp.data[i];

        this->img = new RGB*[bmp.ih.Height];
        for(i = 0; (int)i < bmp.ih.Height; i++) this->img[i] = bmp.img[i];

        ui32 sz = 0; // Copying name
        while(bmp.name[sz++] != 0) {} // -Getting name size.
        this->name = new char[sz];
        for(i = 0; i < sz; i++) this->name[i] = bmp.name[i];
    }
    return *this;
}

void encrypt(Bitmap& bmp, const AES& e) {
    int sz = -1; // -Creating name for the .kiv
    char* kivName, *keyName; int i;               // file
    while(bmp.name[++sz] != 0) {}
    kivName = new char[sz+5];
    keyName = new char[sz+5];
    for(i = 0; i < sz; i++) kivName[i] = bmp.name[i];
    kivName[i++] = '.';
    kivName[i++] = 'k';
    kivName[i++] = 'i';
    kivName[i++] = 'v';
    kivName[i] = 0;
    for(i = 0; i < sz && bmp.name[i] != '.'; i++) kivName[i] = bmp.name[i];
    keyName[i++] = '.';
    keyName[i++] = 'k';
    keyName[i++] = 'e';
    keyName[i++] = 'y';
    keyName[i] = 0;
    // Encryption
    e.saveKey(keyName);
    e.writeKIV(e.encryptCBC(bmp.data, bmp.ih.SizeOfBitmap), kivName);
    bmp.save(bmp.name);
    delete[] kivName;
    delete[] keyName;
}

void decrypt(Bitmap& bmp, const AES& e, int iv) {
    e.decryptCBC(bmp.data, bmp.ih.SizeOfBitmap, iv);
    bmp.save(bmp.name);
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
