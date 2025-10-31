#include"../include/data_randomness.hpp"
#include<cmath>		// For abs, sqrt, ...
#include<stdexcept>

DataRandomness::~DataRandomness(){
    if(this->rmetrics != NULL) delete this->rmetrics;
}

void DataRandomness::calculate_entropy() {						                // -Using Shannon entropy model
	double temp_entropy = 0.0, probability;
	for(const size_t& freq : byteValueFrequence) {
		if (freq > 0) {
			probability = static_cast<double>(freq) / this->data_size;
			temp_entropy -= probability * std::log2(probability);
		}
	}
	this->rmetrics->Entropy = temp_entropy;
}

void DataRandomness::calculate_ChiSquare() {
	double temp_ChiSquare = 0.0;
	for (const size_t& freq : byteValueFrequence){
		temp_ChiSquare += static_cast<double>(freq*freq);
	}
	temp_ChiSquare *= 256.0/this->data_size;
	temp_ChiSquare -= this->data_size;
	this->rmetrics->ChiSquare = temp_ChiSquare;
}

DataRandomness::DataRandomness(const std::vector<std::byte>& data) : data_size(data.size()) {
	if(data.empty()) {
	    throw std::runtime_error("Empty data set.");
	}
	this->rmetrics = new RandomnessMetrics;
	for(const std::byte& byte : data) {				// Establishing the frequency of each of the possible values for a byte.
		byteValueFrequence[static_cast<uint8_t>(byte)]++;
	}
	this->calculate_entropy();
	this->calculate_ChiSquare();
	this->rmetrics->CorrelationAdjacentByte = this->calculateCorrelation(data, 1);
}

double DataRandomness::calculateCorrelation(const std::vector<std::byte>& data, size_t offset) const { // Correlation is (arguably) better as a method since it requires an extra parameter.
	double average = 0.0;
	double variance = 0.0;
	double covariance = 0.0;
	size_t i, j, sz = data.size();

	for(i = 0; i < sz; i++) average += static_cast<double>(data[i]);
	average /= static_cast<double>(sz);

	for(i = 0, j = offset; j < sz; i++, j++){
		variance   += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[i]) - average);
		covariance += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[j]) - average);
	}
	for(j = 0; i < sz; i++, j++){
		variance   += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[i]) - average);
		covariance += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[j]) - average);
	}
	variance   /= static_cast<double>(sz);
	covariance /= static_cast<double>(sz);
	return covariance/variance;
}

double DataRandomness::getEntropy() const noexcept { return this->rmetrics->Entropy; }
double DataRandomness::getChiSquare() const noexcept { return this->rmetrics->ChiSquare; }
double DataRandomness::getCorrelationAdjacentByte() const noexcept { return this->rmetrics->CorrelationAdjacentByte; }
