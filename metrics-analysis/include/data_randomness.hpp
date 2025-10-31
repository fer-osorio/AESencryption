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
	struct RandomnessMetrics* rmetrics = nullptr;
	size_t data_size = 0;
	size_t byteValueFrequence[256] = {0};

	/**
	 * Functions include jump_size to be capable of analysing structured data sets. For example, analyse the randomness metrics for the green component of the
	 * pixels of an image.
	 */
	void get_byteValueFrequence(const std::vector<std::byte>& data, size_t start, size_t jump_size);
	void calculate_entropy();
	void calculate_ChiSquare();
	static double calculateCorrelationSubArray(const std::vector<std::byte>& data, size_t start, size_t jump_size, size_t offset);

	DataRandomness() = default;						// -Private constructor, only accessible inside the class
	DataRandomness(const DataRandomness&);					// -Not allowing copy contructor or
	DataRandomness& operator = (const DataRandomness&);			//  copy assigment

public:
	explicit DataRandomness(const std::vector<std::byte>& data);
	~DataRandomness();

	static double calculateCorrelation(const std::vector<std::byte>& data, size_t offset);
	/**
	 * @brief Computes the randomness metrics on the bytes holded by the 'data' vector and separated by an specyfied amount.
	 * @param jump_size The separation of the bytes being analyzed.
	 * @return DataRandomness class instance containing the result.
	*/
	static DataRandomness calculateDataRandomnessSubArray(const std::vector<std::byte>& data, size_t start, size_t jump_size);

	double getEntropy() const noexcept;
	double getChiSquare() const noexcept;
	double getCorrelationAdjacentByte() const noexcept;
};