#include "File.h"

#include <fstream>
#include <filesystem>
#include <sstream>

Buffer readBinaryFile(const std::string& filePath)
{
	if (!std::filesystem::exists(filePath)) 
	{
		throw std::runtime_error(filePath + "does not exist");
	}

	const size_t fileSize = std::filesystem::file_size(filePath);

	std::ifstream fileStream(filePath.c_str(), std::ios::binary);
	if (!fileStream.is_open())
	{
		throw std::runtime_error("Failed to open " + filePath);
	}

	Buffer fileContent(fileSize);
	fileStream.read(fileContent.data(), static_cast<int64_t>(fileSize));

	return fileContent;
}

std::vector<std::string> readFileLines(const std::string& filePath)
{
	std::vector<std::string> lines;

	if (!std::filesystem::exists(filePath))
	{
		throw std::runtime_error(filePath + "does not exist");
	}

	std::ifstream fileStream(filePath);
	if (!fileStream.is_open())
	{
		throw std::runtime_error("Failed to open " + filePath);
	}

	std::string line;
	while (std::getline(fileStream, line))
	{
		lines.emplace_back(line);
	}

	return lines;
}

void writeToFile(const std::string& filePath, const std::stringstream& ss, bool append)
{
	writeToFile(filePath, ss.str(), append);
}

void writeToFile(const std::string& filePath, const std::string& strToWrite, bool append)
{
	const int mode = append ? std::ios::app : std::ios::out;

	std::ofstream outputFile(filePath, mode);
	if (!outputFile.is_open())
	{
		throw std::runtime_error("Failed to open " + filePath);
	}

	outputFile << strToWrite;
}

void writeToBinaryFile(const std::string& filePath, const std::string& strToWrite)
{
	std::ofstream outputFile(filePath, std::ios::binary);
	if (!outputFile.is_open())
	{
		throw std::runtime_error("Failed to open " + filePath);
	}

	outputFile << strToWrite;
}
