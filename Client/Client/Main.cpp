#include "AutoWsa.h"
#include "MessageClient.h"

#include <iostream>

int main()
{
	try
	{
		AutoWsa wsa;

		MessageClient messageClient;
	}
	catch (const std::exception& exception)
	{
		std::cout << exception.what() << std::endl;
	}

	return 0;
}
