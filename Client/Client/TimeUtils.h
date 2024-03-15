#pragma once

#include <chrono>

inline int64_t getCurrentTimestamp()
{
	auto currentTimePoint = std::chrono::system_clock::now();

	auto durationSinceEpoch = currentTimePoint.time_since_epoch();

	return std::chrono::duration_cast<std::chrono::nanoseconds>(durationSinceEpoch).count();
}
