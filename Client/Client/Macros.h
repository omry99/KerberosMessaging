#pragma once

#define DELETE_COPY_CTOR(className) className(className&) = delete
#define DELETE_MOVE_CTOR(className) className(className&&) = delete
#define DELETE_COPY_OPERATOR(className) className& operator=(className&) = delete
#define DELETE_MOVE_OPERATOR(className) className& operator=(className&&) = delete

#define DELETE_COPY(className); DELETE_COPY_CTOR(className); \
							    DELETE_COPY_OPERATOR(className)

#define DELETE_MOVE(className) DELETE_MOVE_CTOR(className); \
							   DELETE_MOVE_OPERATOR(className)
