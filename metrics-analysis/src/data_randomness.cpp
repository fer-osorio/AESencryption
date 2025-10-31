#include"../include/data_randomness.hpp"
#include<cmath>		// For abs, sqrt, ...
#include<stdexcept>

DataRandomness::~DataRandomness(){
    if(this->rmetrics != NULL) delete this->rmetrics;
}

void DataRandomness::get_byteValueFrequence(const std::vector<std::byte>& data, size_t start, size_t jump_size){
    if(start == 0 && jump_size == 0) {
        for(const std::byte& byte : data) {				                            // Establishing the frequency of each of the possible values for a byte.
		    this->byteValueFrequence[static_cast<uint8_t>(byte)]++;
	    }
	}
	else {
	    size_t sz = data.size(), i = start < sz ? start : start % sz;
	    for(; i < sz; i += jump_size){
	        this->byteValueFrequence[static_cast<uint8_t>(data[i])]++;
	    }
	}
}

void DataRandomness::calculate_entropy() {						                // -Using Shannon entropy model
	double temp_entropy = 0.0, probability;
	for(const size_t& freq : this->byteValueFrequence) {
		if (freq > 0) {
			probability = static_cast<double>(freq) / this->data_size;
			temp_entropy -= probability * std::log2(probability);
		}
	}
	this->rmetrics->Entropy = temp_entropy;
}

void DataRandomness::calculate_ChiSquare() {
	double temp_ChiSquare = 0.0;
	for (const size_t& freq : this->byteValueFrequence){
		temp_ChiSquare += static_cast<double>(freq*freq);
	}
	temp_ChiSquare *= 256.0/this->data_size;
	temp_ChiSquare -= this->data_size;
	this->rmetrics->ChiSquare = temp_ChiSquare;
}

double DataRandomness::calculateCorrelationSubArray(const std::vector<std::byte>& data, size_t start, size_t jump_size, size_t offset) {
	double average = 0.0;
	double variance = 0.0;
	double covariance = 0.0;
	size_t data_size = data.size();
    size_t subdata_size;
    size_t offset_jump;
	size_t i, j;

    if(start >= data.size()) start %= data.size();
    if(jump_size >= data.size()) jump_size %= data.size();
    if(offset >= data.size()) offset %= data.size();

    subdata_size = (jump_size == 0 ? jump_size = 1 : jump_size) == 1 ? data.size() : data.size() / jump_size;
    offset_jump = offset*jump_size;
    if(offset_jump >= data_size) offset_jump %= data_size;

	for(i = 0, j = start; j < data_size; i++, j += jump_size) {
	    average += static_cast<double>(data[j]);
	}
	for(j -= data_size; i < subdata_size; i++, j += jump_size){
	    average += static_cast<double>(data[j]);
	}
	average /= static_cast<double>(subdata_size);

    size_t second_start = (start + offset_jump);
    if(start < second_start) {
        i = start, j = second_start;
    } else{
        i = second_start, j = start;
    }
	for(; j < data_size; i += jump_size, j += jump_size){
		variance   += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[i]) - average);
		covariance += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[j]) - average);
	}
	for(j -= data_size; i < data_size; i += jump_size, j += jump_size){
		variance   += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[i]) - average);
		covariance += (static_cast<double>(data[i]) - average)*(static_cast<double>(data[j]) - average);
	}
	variance   /= static_cast<double>(subdata_size);
	covariance /= static_cast<double>(subdata_size);
	return covariance/variance;
}

DataRandomness::DataRandomness(const std::vector<std::byte>& data) : data_size(data.size()) {
	if(data.empty()) {
	    throw std::runtime_error("Empty data set.");
	}
	this->rmetrics = new RandomnessMetrics;
	this->get_byteValueFrequence(data, 0, 0);
	this->calculate_entropy();
	this->calculate_ChiSquare();
	this->rmetrics->CorrelationAdjacentByte = this->calculateCorrelation(data, 1);
}

double DataRandomness::calculateCorrelation(const std::vector<std::byte>& data, size_t offset) {
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

DataRandomness DataRandomness::calculateDataRandomnessSubArray(const std::vector<std::byte> &data, size_t start, size_t jump_size){
    DataRandomness result;
    if(result.rmetrics == nullptr) result.rmetrics = new RandomnessMetrics;
	result.get_byteValueFrequence(data, start, jump_size);
	result.calculate_entropy();
	result.calculate_ChiSquare();
	calculateCorrelationSubArray(data, start, jump_size, 1);
	return result;
}

double DataRandomness::getEntropy() const noexcept {
    return this->rmetrics->Entropy;
}
double DataRandomness::getChiSquare() const noexcept {
    return this->rmetrics->ChiSquare;
}
double DataRandomness::getCorrelationAdjacentByte() const noexcept {
    return this->rmetrics->CorrelationAdjacentByte;
}
