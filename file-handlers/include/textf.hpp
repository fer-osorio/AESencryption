#include"../include/file_base.hpp"
#include<iostream>

namespace File {

class TXT : private FileBase {
	public:
	TXT(const std::filesystem::path& path);					// -Building from file.

	void load() override;							// Override, loading as text
	void save(const std::filesystem::path& output_path) const override;	// Override, saving as text
};

} // namespace File