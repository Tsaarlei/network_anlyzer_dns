cmake_minimum_required(VERSION 4.3)
project(sniffer C)

set(CMAKE_C_STANDARD 11)

add_executable(sniffer main.c
        dns_handler.h
        asciiArtAndStart.h)
