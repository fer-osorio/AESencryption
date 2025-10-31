#include<cstddef>
#include<stdint.h>
#include<vector>

class DataRandomness {								// -Specialized to handle data from raw bytes
private:
	struct RandomnessMetrics{
		double Entropy;
		double ChiSquare;
		double CorrelationAdjacentByte;
	};
	struct RandomnessMetrics* rmetrics = NULL;
	size_t data_size = 0;
	size_t byteValueFrequence[256];

	virtual void get_byteValueFrequence(const std::vector<std::byte>& data);
	virtual void calculate_entropy();
	virtual void calculate_ChiSquare();

public:
	//DataRandomness() = default;						// -Rule of Zero: No need for manual copy/assignment/destructor.
										//  The compiler-generated ones are correct.
	explicit DataRandomness(const std::vector<std::byte>& data);
	virtual ~DataRandomness();

	static double calculateCorrelation(const std::vector<std::byte>& data, size_t offset);

	double getEntropy() const noexcept;
	double getChiSquare() const noexcept;
	double getCorrelationAdjacentByte() const noexcept;
};