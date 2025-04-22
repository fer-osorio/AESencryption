#include<iostream>
#include<string.h>
#include"../Source/File.hpp"
#include<plplot/plstream.h>

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

    void catNameNoextensionNoslash(char* destination) const;
    void makePlotLabel(File::Bitmap::ColorID CID, char* destination, const char* prefix = NULL, int direction = -1) const;
    void makePlotName(File::Bitmap::ColorID CID, char* destination, const char* prefix = NULL, const char* postfix = NULL, int direction = -1) const;
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
    double correlationGraph(File::Bitmap::ColorID CID,
                            File::Bitmap::Direction dr,
                            const char* CGname = NULL,                          //  -Correlation Graph name
                            const char* CGlabel = NULL,                         //  -Correlation Graph label
                            char sym = '.',                                     //  -Symbol to be used in the graph
                            size_t ssym = 1) const;                             //  -Factor of scaling for symbol size
};

int main(int argc, const char* argv[]){
    if(argc == 4){
        File::Bitmap bmp;
        uint32_t ssym;
        int r;
        char sym = argv[2][0];
        try{
            bmp = File::Bitmap(argv[1]);
            ssym = uint32_t((r = std::stoi(argv[3])) < 0 ? -r : r);
        } catch(const std::runtime_error& exp){
            std::cout << "Could not open bitmap file..." << exp.what() << "\n";
            return 0;
        } catch(const std::invalid_argument& exp){
            std::cout << "std::invalid_argument::what(): " << exp.what() << '\n' << "Procceding with ssym = 1\n";
            ssym = 1;
        } catch(const std::out_of_range& exp){
            std::cout << "std::out_of_range::what(): " << exp.what() << '\n' << "Procceding with ssym = 1\n";
            ssym = 1;
        }
        PlotBmpStats pl(bmp);
        int i, j;
        for(i = 0; i < RGB_COMPONENTS_AMOUNT; i++){
            pl.histogram((File::Bitmap::ColorID)i);
            for(j = 0; j < DIRECTIONS_AMOUNT; j++){
                pl.correlationGraph((File::Bitmap::ColorID)i, (File::Bitmap::Direction)j, NULL, NULL, sym, ssym);
            }
        }
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

void PlotBmpStats::catNameNoextensionNoslash(char *destination) const{
    char bmpName[NAME_MAX_LEN];
    int i = 0;
    this->writeBmpName(bmpName);
    while(bmpName[i] != 0) {i++;}
    while(bmpName[i] != '.') {i--;}
    if(i >= 0 && strcmp(bmpName + i, ".bmp") == 0) bmpName[i] = 0;
    while(bmpName[i] != '/') {i--;}
    if(i >= 0) strcat(destination, bmpName+i+1);
    else strcat(destination, bmpName);
}

void PlotBmpStats::makePlotLabel(File::Bitmap::ColorID CID, char *destination, const char* prefix, int direction) const{
    if(prefix != NULL) {
        strcpy(destination, prefix);
        strcat(destination, " ");
    }
    else destination[0] = 0;
    this->catNameNoextensionNoslash(destination);
    strcat(destination, " ");
    if(direction > -1 && direction < DIRECTIONS_AMOUNT){
        strcat(destination, File::Bitmap::DirectionLabels[direction]);
        strcat(destination, " ");
    }
    strcat(destination, File::Bitmap::RGBlabels[CID]);

}

void PlotBmpStats::makePlotName(File::Bitmap::ColorID CID, char *destination, const char* prefix, const char* postfix, int direction) const{
    if(prefix != NULL) strcpy(destination, prefix);
    else destination[0] = 0;
    this->catNameNoextensionNoslash(destination);
    if(direction > -1 && direction < DIRECTIONS_AMOUNT) strcat(destination, File::Bitmap::DirectionLabels[direction]);
    strcat(destination, File::Bitmap::RGBlabels[CID]);
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

double PlotBmpStats::correlationGraph(File::Bitmap::ColorID CID, File::Bitmap::Direction dr, const char *CGname, const char* CGlabel, char sym, size_t ssym) const{
    plstream pCG;                                                               // Plot correlation Graph
    double c = this->retreaveCorrelation(CID, dr);
    if(c < 0) c = -c;
    if(CGlabel != NULL && CGname != NULL) this->initializeGraph(&pCG, CGname, 10, 256, 253, "Pixel value (i,j)", "Pixel value (i+1,j+1)", CGlabel, 3);
    else {
        char plotLabel[NAME_MAX_LEN];
        char plotName[NAME_MAX_LEN];
        this->makePlotLabel(CID, plotLabel,"Graph Correlation ", dr);
        this->makePlotName(CID, plotName, "GraphCorrelation",".png", dr);
        this->initializeGraph(&pCG, plotName, 10, 256, 253, "Pixel value (i,j)", "Pixel value (i+1,j+1)", plotLabel, this->toPlplotColor(CID));
    }
    if(sym < 0) sym += 128;
    if(ssym > 10) ssym = 10;
    pCG.ssym(0.0, ssym);
    pCG.poin(this->pixelAmount(), this->X[CID][dr], this->Y[CID][dr], sym); // Draw the scatter points with symbol .
    return this->retreaveCorrelation(CID, dr);
}
