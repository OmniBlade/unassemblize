/**
 * @file
 *
 * @brief Embedded git information.
 *
 * @copyright Assemblize is free software: you can redistribute it and/or
 *            modify it under the terms of the GNU General Public License
 *            as published by the Free Software Foundation, either version
 *            3 of the License, or (at your option) any later version.
 *            A full copy of the GNU General Public License can be found in
 *            LICENSE
 */
#pragma once

#include <time.h>

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

extern const char GitSHA1[];
extern const char GitShortSHA1[];
extern const char GitCommitDate[];
extern const char GitCommitAuthorName[];
extern const char GitTag[];
extern time_t GitCommitTimeStamp;
extern bool GitUncommittedChanges;
extern bool GitHaveInfo;
extern int GitRevision;

#ifdef __cplusplus
} // extern "C"
#endif
