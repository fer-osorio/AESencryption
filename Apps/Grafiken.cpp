#include<iostream>
#include<string.h>
#include"../Source/File.hpp"
#include<plplot/plstream.h>
//#include<plstream.h>

struct PlotBmpStats: public File::BitmapStatistics {
    private:
    double* X[RGB_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT] ={  {NULL,NULL,NULL},
                                                            {NULL,NULL,NULL},
                                                            {NULL,NULL,NULL}};

    double* Y[RGB_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT] ={  {NULL,NULL,NULL},
                                                            {NULL,NULL,NULL},
                                                            {NULL,NULL,NULL}};
    double  H[RGB_COMPONENTS_AMOUNT][256] = {0};

    void initializeGraph(plstream*const pl,                                     //  Initialize plstream object pointed by pl using the provided arguments
                         const char* fname,                                     //  File name
                         int axisColor,
                         double Xmax,                                           //  Initializing maxumum values for axis. Minimum is setted as 0.0
                         double Ymax,                                           //  ...
                         const char* Xlabel,                                    //  Setting axis labels
                         const char* Ylabel,                                    //  ...
                         const char* graphlabel,
                         int graphColor,                                        //  Determines color weill be use for the graphic
                         const char* sdev = "pngcairo") const;                  //  Output device

    void makePlotLabel(File::Bitmap::ColorID CID, char* destination, const char* prefix = NULL) const;
    void makePlotName(File::Bitmap::ColorID CID, char* destination, const char* prefix = NULL, const char* postfix = NULL) const;
    int toPlplotColor(File::Bitmap::ColorID CID) const;

    public:
    PlotBmpStats(const File::Bitmap& bmp);
    PlotBmpStats(const PlotBmpStats& pbs);
    ~PlotBmpStats(){
        for(int i = 0, j; i < RGB_COMPONENTS_AMOUNT; i++){
            for(j = 0; j < DIRECTIONS_AMOUNT; j++){
                if(this->X[i][j] != NULL) delete this->X[i][j];
                if(this->Y[i][j] != NULL) delete this->Y[i][j];
            }
        }
    }
    PlotBmpStats& operator=(const PlotBmpStats& pbs);
    double histogram(File::Bitmap::ColorID CID, const char* Hname = NULL, const char* Hlabel = NULL) const;
    double correlationGraph(File::Bitmap::ColorID CID, File::Bitmap::Direction dr, const char* CGname = NULL, const char* CGlabel = NULL) const;
};

int main(int argc, const char* argv[]){
    if(argc == 3){
        AES::Key k;
        try{
            k = AES::Key(argv[1]);
        } catch(const std::runtime_error& exp){
            std::cout << "Could not open aeskey file..." << exp.what() << "\n";
            return 0;
        }
        AES::Cipher ch(k);
        File::Bitmap bmp;
        try{
            bmp = File::Bitmap(argv[2]);
        } catch(const std::runtime_error& exp){
            std::cout << "Could not open bitmap file..." << exp.what() << "\n";
            return 0;
        }
        PlotBmpStats pl(bmp);
        pl.correlationGraph(File::Bitmap::Blue, File::Bitmap::diagonal);
        pl.histogram(File::Bitmap::Red);
    }
    return 0;
}

PlotBmpStats::PlotBmpStats(const File::Bitmap& bmp): File::BitmapStatistics(&bmp){
    int i, j;
    for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++){
        this->writeHistogram((File::Bitmap::ColorID)i, this->H[i]);
        for(j = 0; j < DIRECTIONS_AMOUNT; j++){
            if(this->X[i][j] == NULL) this->X[i][j] = new double[this->pixelAmount()];
            if(this->Y[i][j] == NULL) this->Y[i][j] = new double[this->pixelAmount()];
            this->retreaveCorrelation((File::Bitmap::ColorID)i, (File::Bitmap::Direction)j, this->X[i][j], this->Y[i][j]);
        }
    }
}

PlotBmpStats::PlotBmpStats(const PlotBmpStats& pbs): File::BitmapStatistics(pbs){
    for(int i = 0, j; i < RGB_COMPONENTS_AMOUNT; i++){
        pbs.writeHistogram((File::Bitmap::ColorID)i, this->H[i]);
        for(j = 0; j < DIRECTIONS_AMOUNT; j++){
            this->X[i][j] = new double[this->pixelAmount()];
            this->Y[i][j] = new double[this->pixelAmount()];
            pbs.retreaveCorrelation((File::Bitmap::ColorID)i, (File::Bitmap::Direction)j, this->X[i][j], this->Y[i][j]);
        }
    }
}

PlotBmpStats& PlotBmpStats::operator=(const PlotBmpStats &pbs){
    if(this != &pbs){
        BitmapStatistics::operator=(pbs);
    }
    for(int i = 0, j; i < RGB_COMPONENTS_AMOUNT; i++){
        pbs.writeHistogram((File::Bitmap::ColorID)i, this->H[i]);
        for(j = 0; j < DIRECTIONS_AMOUNT; j++){
            if(this->X[i][j] == NULL) this->X[i][j] = new double[this->pixelAmount()];
            if(this->Y[i][j] == NULL) this->Y[i][j] = new double[this->pixelAmount()];
            pbs.retreaveCorrelation((File::Bitmap::ColorID)i, (File::Bitmap::Direction)j, this->X[i][j], this->Y[i][j]);
        }
    }
    return *this;
}

void PlotBmpStats::initializeGraph( plstream*const pl,
                                    const char* name,
                                    int axisColor,
                                    double Xmax,
                                    double Ymax,
                                    const char* Xlabel,
                                    const char* Ylabel,
                                    const char* graphlabel,
                                    int graphColor,
                                    const char* sdev) const{
    pl->sdev(sdev);
    pl->sfnam(name);                                                            // A good default name could be the bmp name concatenated with "Histogram"
    pl->scolbg(240, 240, 240);
    pl->init();
    pl->col0(axisColor);                                                        // Set axis color
    pl->env(0, Xmax, 0, Ymax, 0, 0);                                            // Set up the plotting area
    pl->lab(Xlabel, Ylabel, graphlabel);
    pl->col0(graphColor);
}

void PlotBmpStats::makePlotLabel(File::Bitmap::ColorID CID, char *destination, const char* prefix) const{
    const char* colorLabel = File::Bitmap::RGBlabels[CID];
    char bmpName[NAME_MAX_LEN];
    this->writeBmpName(bmpName);
    if(prefix != NULL) {
        strcpy(destination, prefix);
        strcat(destination, " ");
    }
    else destination[0] = 0;
    strcat(destination, bmpName);
    strcat(destination, " ");
    strcat(destination, colorLabel);
}

void PlotBmpStats::makePlotName(File::Bitmap::ColorID CID, char *destination, const char* prefix, const char* postfix) const{
    const char* colorLabel = File::Bitmap::RGBlabels[CID];
    char bmpName[NAME_MAX_LEN];
    this->writeBmpName(bmpName);
    if(prefix != NULL) strcpy(destination, prefix);
    else destination[0] = 0;
    strcat(destination, bmpName);
    strcat(destination, colorLabel);
    if(postfix != NULL) strcat(destination, postfix);
}

int PlotBmpStats::toPlplotColor(File::Bitmap::ColorID CID) const{
    switch(CID){
        case File::Bitmap::Red:
            return 1;
            break;
        case File::Bitmap::Green:
            return 3;
            break;
        case File::Bitmap::Blue:
            return 9;
            break;
    }
    return 9;
}

double PlotBmpStats::histogram(File::Bitmap::ColorID CID, const char* Hname, const char* Hlabel) const{
    plstream phist;                                                             // Plot histogram
    double I[256], max;
    int i = 0;
    for(i = 0, max = this->H[CID][0]; i < 256; i++) {
        if(max < this->H[CID][i]) max = this->H[CID][i];
        I[i] = (double)i;
    }                                                                           // A good default label could be the name of bmp with the color
    if(Hlabel != NULL && Hname != NULL) this->initializeGraph(&phist, Hname, 10, 256, max*1.2, "Pixel value", "Frequence", Hlabel, 3);
    else {
        char plotLabel[NAME_MAX_LEN];
        char plotName[NAME_MAX_LEN];
        this->makePlotLabel(CID, plotLabel,"Histograma ");
        this->makePlotName(CID, plotName, "Histograma",".png");
        this->initializeGraph(&phist, plotName, 10, 256, max*1.2, "Pixel value", "Frequence", plotLabel, this->toPlplotColor(CID));
    }
    phist.bin(256, I, this->H[CID], PL_BIN_CENTRED | PL_BIN_NOEXPAND);          // Draw histogram
    return this->retreaveEntropy(CID);
}

double PlotBmpStats::correlationGraph(File::Bitmap::ColorID CID, File::Bitmap::Direction dr, const char *CGname, const char* CGlabel) const{
    plstream pCG;                                                               // Plot correlation Graph
    double c = this->retreaveCorrelation(CID, dr);
    if(c < 0) c = -c;
    if(CGlabel != NULL && CGname != NULL) this->initializeGraph(&pCG, CGname, 10, 256, 253, "Pixel value (i,j)", "Pixel value (i+1,j+1)", CGlabel, 3);
    else {
        char plotLabel[NAME_MAX_LEN];
        char plotName[NAME_MAX_LEN];
        this->makePlotLabel(CID, plotLabel,"Graph Correlation ");
        this->makePlotName(CID, plotName, "GraphCorrelation",".png");
        this->initializeGraph(&pCG, plotName, 10, 256, 253, "Pixel value (i,j)", "Pixel value (i+1,j+1)", plotLabel, this->toPlplotColor(CID));
    }
    if(c >= 0.9){
        pCG.ssym(0.0, 1);
        pCG.poin(this->pixelAmount(), this->X[CID][dr], this->Y[CID][dr], '+'); // Draw the scatter points with symbol +
    }
    if(c < 0.9 && c >= 0.01 ) pCG.poin(this->pixelAmount(), this->X[CID][dr], this->Y[CID][dr], '.'); // Draw the scatter points with symbol .
    else {
        pCG.ssym(0.0, 0.3);
        pCG.poin(this->pixelAmount(), this->X[CID][dr], this->Y[CID][dr], '.'); // Draw the scatter points with symbol .
    }
    return this->retreaveCorrelation(CID, dr);
}
