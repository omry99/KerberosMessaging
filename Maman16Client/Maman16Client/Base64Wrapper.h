﻿#pragma once

#include <base64.h>

#include <string>


class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
