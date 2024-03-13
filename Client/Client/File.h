#pragma once

#include <string>
#include <sstream>
#include <vector>

std::vector<std::string> readFileLines(const std::string& filePath);

void writeToFile(const std::string& filePath, const std::stringstream& ss, bool append = false);

void writeToFile(const std::string& filePath, const std::string& strToWrite, bool append = false);

