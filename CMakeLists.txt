cmake_minimum_required(VERSION 3.16)
project(HTTP_Server ASIO)

# Установочные сборы Boost (автоматически находит в системе или указывает путь)
find_package(boost-asyncio REQUIRED COMPONENTS asio)

set(CMAKE_CXX_STANDARD 20)