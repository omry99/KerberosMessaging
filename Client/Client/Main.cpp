#include "AutoWsa.h"
#include "FileClient.h"

#include <iostream>

int main()
{
	try
	{
		AutoWsa wsa;

		FileClient fileClient;
		fileClient.sendFile();
	}
	catch (const std::exception& exception)
	{
		std::cout << exception.what() << std::endl;
	}

	return 0;
}
