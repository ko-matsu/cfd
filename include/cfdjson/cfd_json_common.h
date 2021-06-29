// Copyright 2021 CryptoGarage
/**
 * @file cfd_json_common.h
 * @brief Common definition file for cfd.
 */
#ifndef CFD_INCLUDE_CFDJSON_CFD_JSON_COMMON_H_
#define CFD_INCLUDE_CFDJSON_CFD_JSON_COMMON_H_
#include <cstddef>
#include <cstdint>

/**
 * @brief API DLL export definition
 */
#ifndef CFDJSON_API
#if defined(_WIN32)
#ifdef CFDJSON_BUILD
#define CFDJSON_API __declspec(dllexport)
#elif defined(CFDJSON_SHARED)
#define CFDJSON_API __declspec(dllimport)
#else
#define CFDJSON_API
#endif
#elif defined(__GNUC__) && defined(CFDJSON_BUILD)
#define CFDJSON_API __attribute__((visibility("default")))
#else
#define CFDJSON_API
#endif
#endif

/**
 * @brief DLL export definition for class
 */
#ifndef CFDJSON_EXPORT
#if defined(_WIN32)
#ifdef CFDJSON_BUILD
#define CFDJSON_EXPORT __declspec(dllexport)
#elif defined(CFDJSON_SHARED)
#define CFDJSON_EXPORT __declspec(dllimport)
#else
#define CFDJSON_EXPORT
#endif
#elif defined(__GNUC__) && defined(CFDJSON_BUILD)
#define CFDJSON_EXPORT __attribute__((visibility("default")))
#else
#define CFDJSON_EXPORT
#endif
#endif

#endif  // CFD_INCLUDE_CFDJSON_CFD_JSON_COMMON_H_
