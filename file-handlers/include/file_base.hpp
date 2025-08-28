#ifndef FILE_BASE_HPP
#define FILE_BASE_HPP

#include<vector>
#include<string>
#include<filesystem> // For path handling
#include<map>
#include<stdexcept>  // For exceptions

// Forward declaration of the Encryptor interface.
class Encryptor;

// Forward declaration of the DataRandomness interface.
struct DataRandomness;

/**
 * @class FileBase
 * @brief An abstract base class for representing a file's content.
 *
 * This class provides a common interface for loading, saving, and analyzing
 * file data. It uses modern C++ idioms like RAII to ensure memory safety.
 */
class FileBase {
protected:
	// Using std::filesystem::path is best practice for handling file paths.
	// It correctly handles different OS path separators ('/' vs '\').
	std::filesystem::path file_path;

	// std::vector<uint8_t> is the key improvement.
	// - It manages its own memory (no manual new/delete).
	// - It knows its own size (no separate 'size' variable needed).
	// - It provides safe access to the data.
	std::vector<uint8_t> data;

public:
	/**
	* @brief Constructs a FileBase object from a given path.
	* @param path The path to the file.
	*/
	explicit FileBase(const std::filesystem::path& path);

	// Virtual destructor is crucial for a base class.
	// It ensures that when you delete a derived class through a base class
	// pointer, the derived class's destructor is called first.
	virtual ~FileBase() = default;

	// --- Core Public Interface ---

	/**
	* @brief Loads the file content from the stored path into the data buffer.
	* @return True if loading was successful, false otherwise.
	* * Marked as 'virtual' so derived classes can provide specialized
	* loading mechanisms (e.g., text vs. binary mode).
	*/
	virtual bool load();

	/**
	* @brief Saves the current data buffer to a specified path.
	* @param output_path The path to save the file to.
	* @return True if saving was successful, false otherwise.
	*/
	virtual bool save(const std::filesystem::path& output_path) const;

	/**
	* @brief Applies an encryption/decryption algorithm to the file's data.
	* @param algorithm An object that conforms to the Encryptor interface.
	* * This method modifies the internal data buffer.
	*/
	void apply_encryption(const Encryptor& c);

	/**
	* @brief Calculates various statistics on the current data buffer.
	* @return A DataRandomness struct containing the results.
	* * Marked as 'virtual' because subclasses might want to add more
	* specific statistics (e.g., word count for a text file).
	*/
	virtual DataRandomness calculate_statistics() const;

	// --- Accessors (Getters) ---

	const std::filesystem::path& get_path() const;
	const std::vector<uint8_t>& get_data() const;
	size_t get_size() const;
};

#endif // FILE_BASE_HPP