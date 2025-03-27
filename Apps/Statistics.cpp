#include"../Source/File.hpp"
#include<tgmath.h>
#define KEY_SIZES_AMOUNT  3
#define OPERATION_MODES_AMOUNT 3
#define MAX_TEST_AMOUND 1024

static double maximum(const double data[], const size_t size);
static double minimum(const double data[], const size_t size);
static double average(const double data[], const size_t size);
static double averageAbsoluteDeviation(const double data[], const size_t size, const double avr);
static double chiSquarePercentagePointsAprox(uint32_t v, double xp);

struct StatisticalDispersion{
    private:
    double Maximum = 0.0;
    double Minimum = 0.0;
    double Average = 0.0;
    double AverageAbsoluteDeviation = 0.0;

    public:
    StatisticalDispersion(){}
    StatisticalDispersion(const double data[], const size_t size);
    friend std::ostream& operator<<(std::ostream& os, const StatisticalDispersion& sd);

    StatisticalDispersion operator*(const double t) const;
};

int main(int argc, char* argv[]) {
    if(argc == 3) {
        AES::Key key;
        AES::Key::Length klen;
        AES::Key::OperationMode opm;
        AES::Cipher AEScph = AES::Cipher(key);
        File::Bitmap bmp;
        File::BitmapStatistics bmpSts;

        double entropies[OPERATION_MODES_AMOUNT][PIXEL_COMPONENTS_AMOUNT][MAX_TEST_AMOUND];
        StatisticalDispersion Entropy[OPERATION_MODES_AMOUNT][PIXEL_COMPONENTS_AMOUNT];

        double XiSquares[OPERATION_MODES_AMOUNT][PIXEL_COMPONENTS_AMOUNT][MAX_TEST_AMOUND];
        StatisticalDispersion XiSquare[OPERATION_MODES_AMOUNT][PIXEL_COMPONENTS_AMOUNT];

        double correlations[OPERATION_MODES_AMOUNT][PIXEL_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT][MAX_TEST_AMOUND];
        StatisticalDispersion Correlation[OPERATION_MODES_AMOUNT][PIXEL_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT];

        int i, j, k, l, q, r;
        uint32_t testsAmount;

        try {
            bmp = File::Bitmap(argv[1]);
            testsAmount = uint32_t((r = std::stoi(argv[2])) < 0 ? -r : r);
        } catch(std::runtime_error& exp) {;
            std::cerr << "Could not create File::Bitmap object.\n" << exp.what();
            return EXIT_FAILURE;
        } catch(std::invalid_argument& exp){
            std::cout << "std::invalid_argument::what(): " << exp.what() << '\n' << "Procceding with testsAmount = 1\n";
            testsAmount = 1;
        } catch (std::out_of_range& exp)
        {
            std::cout << "std::out_of_range::what(): " << exp.what() << '\n' << "Procceding with testsAmount = 1\n";
            testsAmount = 1;
        }

        if(testsAmount > MAX_TEST_AMOUND){
            std::cout << "Maximum number of tests exceeded. " << "Procceding with testsAmount = 512\n";
            testsAmount = 512;
        }

        const File::Bitmap bmp__ = bmp;
        std::cout << '\n' << argv[1] << " characteristics:\n\n";
        std::cout << bmp << "\n\n";

        std::cout << "\nAverage of statistical measures with " << testsAmount << " tests.\n";
        for(i = 0; i < KEY_SIZES_AMOUNT; i++){
            switch(i){
                case 0: klen = AES::Key::_128;
                    break;
                case 1: klen = AES::Key::_192;
                    break;
                case 2: klen = AES::Key::_256;
                    break;
                default:klen = AES::Key::_256;
            }

            for(j = 0; j < OPERATION_MODES_AMOUNT; j++){
                switch(j){
                    case 0: opm = AES::Key::ECB;
                        break;
                    case 1: opm = AES::Key::CBC;
                        break;
                    case 2: opm = AES::Key::PVS;
                        break;
                    default:opm = AES::Key::ECB;
                }

                for(k = 0; (uint32_t)k < testsAmount; k++) {
                    for(l = 0; l < PIXEL_COMPONENTS_AMOUNT; l++) {
                        entropies[j][l][k] = 0;
                        XiSquares[j][l][k]= 0;
                        for(q = 0; q < DIRECTIONS_AMOUNT; q++) correlations[j][l][q][k] = 0;
                    }
                }

                for(k = 0; (uint32_t)k < testsAmount; k++) {
                    key = AES::Key(klen, opm);
                    AEScph = AES::Cipher(key);
                    encrypt(bmp, AEScph, false);
                    bmpSts = File::BitmapStatistics(&bmp);
                    for(l = 0; l < PIXEL_COMPONENTS_AMOUNT; l++) {
                        entropies[j][l][k] = bmpSts.retreaveEntropy(File::Bitmap::ColorID(l));
                        XiSquares[j][l][k]= bmpSts.retreaveXiSquare(File::Bitmap::ColorID(l));
                        for(q = 0; q < DIRECTIONS_AMOUNT; q++)
                            correlations[j][l][q][k] = bmpSts.retreaveCorrelation(File::Bitmap::ColorID(l), File::Bitmap::Direction(q));
                    }
                    decrypt(bmp, AEScph, false);
                    if(bmp__ != bmp) std::cout << "Something went wrong with decryption" << std::endl;
                }
                for(l = 0; l < PIXEL_COMPONENTS_AMOUNT; l++) {
                    Entropy[j][l] = StatisticalDispersion(entropies[j][l], testsAmount);
                    XiSquare[j][l]= StatisticalDispersion(XiSquares[j][l], testsAmount);
                    for(q = 0; q < DIRECTIONS_AMOUNT; q++) Correlation[j][l][q] = StatisticalDispersion(correlations[j][l][q], testsAmount)*100.0;
                }
            }

            std::cout << std::fixed << std::setprecision(6) <<std::endl;
            std::cout << "Key size = " << (int)klen << " -----------------------------------\n\n";
            std::cout << "Entropy        ECV     CBC     PVS     \n";
            std::cout << "Red          " << Entropy[0][0] << ' ' << Entropy[1][0] << ' ' << Entropy[2][0] << '\n';
            std::cout << "Green        " << Entropy[0][1] << ' ' << Entropy[1][1] << ' ' << Entropy[2][1] << '\n';
            std::cout << "Blue         " << Entropy[0][2] << ' ' << Entropy[1][2] << ' ' << Entropy[2][2] << '\n';

            std::cout << std::endl;

            std::cout << "Percentage points of the Chi-Square distribution at 5%, 25%, 50%, 75% and 95% (plus O(1/sqrt(255))):\n"
            << chiSquarePercentagePointsAprox(255,-1.64)    << ", "
            << chiSquarePercentagePointsAprox(255,-0.674)   << ", "
            << chiSquarePercentagePointsAprox(255,0.0)      << ", "
            << chiSquarePercentagePointsAprox(255,0.674)    << ", "
            << chiSquarePercentagePointsAprox(255,1.64);

            std::cout << std::endl;

            std::cout << std::fixed << std::setprecision(2) <<std::endl;
            std::cout << "XiSquares          ECV        CBC        PVS     \n";
            std::cout << "Red          " << XiSquare[0][0] << ' ' << XiSquare[1][0] << ' ' << XiSquare[2][0] << '\n';
            std::cout << "Green        " << XiSquare[0][1] << ' ' << XiSquare[1][1] << ' ' << XiSquare[2][1] << '\n';
            std::cout << "Blue         " << XiSquare[0][2] << ' ' << XiSquare[1][2] << ' ' << XiSquare[2][2] << '\n';

            std::cout << std::endl;

            std::cout << std::fixed << std::setprecision(6) <<std::endl;
            for(k = 0; k < DIRECTIONS_AMOUNT; k++){
                if(k == File::Bitmap::horizontal) std::cout << "Horizontal Correlation x100    ECV      CBC      PVS     \n";
                if(k == File::Bitmap::vertical)   std::cout << "Vertical Correlation   x100   ECV      CBC      PVS     \n";
                std::cout << "Red                      ";
                for(l = 0; l < OPERATION_MODES_AMOUNT; l++) std::cout << Correlation[l][0][k] << ' ';
                std::cout << '\n' << "Green                    ";
                for(l = 0; l < OPERATION_MODES_AMOUNT; l++) std::cout << Correlation[l][1][k] << ' ';
                std::cout << '\n' << "Blue                     ";
                for(l = 0; l < OPERATION_MODES_AMOUNT; l++) std::cout << Correlation[l][2][k] << ' ';
                std::cout << '\n';
                std::cout << std::endl;
            }
            std::cout << std::endl;
        }
    }
    return 0;
}

double maximum(const double data[], const size_t size) {
    double max = data[0];
    for(size_t i = 0; i < size; i++) if(max < data[i]) max = data[i];
    return max;
}

double minimum(const double data[], const size_t size) {
    double min = data[0];
    for(size_t i = 0; i < size; i++) if(min > data[i]) min = data[i];
    return min;
}

double average(const double data[], const size_t size) {
    double avr = 0.0;
    for(size_t i = 0; i < size; i++) avr += data[i];
    avr /= (double)size;
    return avr;
}

double averageAbsoluteDeviation(const double data[], const size_t size, const double avr) {
    double aad = 0.0, buff = 0.0;
    for(size_t i = 0; i < size; i++) {
        buff = data[i] - avr;
        buff < 0 ? aad -= buff : aad += buff;
    }
    aad /= (double)size;
    return aad;
}

StatisticalDispersion::StatisticalDispersion(const double data[], const size_t size){
    this->Maximum = maximum(data, size);
    this->Minimum = minimum(data, size);
    this->Average = average(data, size);
    this->AverageAbsoluteDeviation = averageAbsoluteDeviation(data, size, this->Average);
}

static std::ostream& withSign(std::ostream& os, double d){
    os << (d < 0 ? "" : " ") << d;
    return os;
}

std::ostream& operator<<(std::ostream& os, const StatisticalDispersion& sd){
    withSign(withSign(withSign(withSign(os << '(', sd.Average) << ' ', sd.AverageAbsoluteDeviation) << ' ', sd.Maximum) << ' ', sd.Minimum) << " ]";
    return os;
}

StatisticalDispersion StatisticalDispersion::operator*(const double t) const{
    StatisticalDispersion r;
    r.Maximum = this->Maximum*t;
    r.Minimum = this->Minimum*t;
    r.Average = this->Average*t;
    r.AverageAbsoluteDeviation = this->AverageAbsoluteDeviation*t;
    return r;
}

double chiSquarePercentagePointsAprox(uint32_t v, double xp){
    return v + sqrt(2*(double)v)*xp + 2*(xp*xp - 1)/3;
}
