#pragma once

#include "Defs.h"

#include <string>
#include <sstream>
#include <vector>

Buffer readBinaryFile(const std::string& filePath);

std::vector<std::string> readFileLines(const std::string& filePath);

void writeToFile(const std::string& filePath, const std::stringstream& ss, bool append = false);

void writeToFile(const std::string& filePath, const std::string& strToWrite, bool append = false);

// TDOo: organize this
void writeToBinaryFile(const std::string& filePath, const std::string& strToWrite);
